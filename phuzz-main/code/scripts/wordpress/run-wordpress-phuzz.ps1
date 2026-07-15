param(
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug = "show-all-comments-in-one-page",
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [switch]$RunGeneratedConfigs,
    [ValidatePattern('^[a-zA-Z0-9_./-]+$')]
    [string]$BootstrapConfigSlug = "",
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [ValidateSet('static', 'dynamic-helper')]
    [string]$ParamDiscoveryMode = 'static',
    [ValidateRange(1, 30)]
    [int]$GeneratedConfigTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginScript = Join-Path $scriptRoot "web\applications\wordpress\_plugins\download-plugins.ps1"
$fuzzerService = "fuzzer-wordpress-plugin"
$webUrl = "http://localhost:8080/"

if (-not $BootstrapConfigSlug) {
    if ($RunGeneratedConfigs) {
        $BootstrapConfigSlug = "wordpress/bootstrap-generated"
    } else {
        $BootstrapConfigSlug = "wordpress/$PluginSlug"
    }
}

function Get-ComposeArgs {
    param([string]$OverridePath)

    return @("docker", "compose", "-f", "docker-compose.yml", "-f", $OverridePath)
}

function Invoke-Compose {
    param(
        [string[]]$ComposeArgs,
        [string[]]$AdditionalArgs
    )

    & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] @AdditionalArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose command failed: $($AdditionalArgs -join ' ')"
    }
}

function New-PluginOverrideFile {
    param(
        [string]$PluginSlug,
        [string]$BootstrapConfigSlug,
        [string]$ParamDiscoveryMode
    )

    $path = Join-Path $env:TEMP ("phuzz-{0}.override.yml" -f $PluginSlug)
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/"
        "      WP_TARGET_PLUGIN: $PluginSlug"
        "      HOOKPHUZZ_PARAM_DISCOVERY_MODE: $ParamDiscoveryMode"
        "      HOOKPHUZZ_HELPER_READER_REGISTRY: /shared-tmpfs/hook-coverage/helper_reader_registry.json"
        "  ${fuzzerService}:"
        "    environment:"
        "      FUZZER_CONFIG: $BootstrapConfigSlug"
    )
    Set-Content -LiteralPath $path -Value $content -Encoding ASCII
    return $path
}

function Publish-HelperReaderRegistry {
    param(
        [string]$ScriptRoot,
        [string[]]$ComposeArgs,
        [string]$PluginSlug,
        [string]$OutputDir
    )

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for helper reader analysis."
    }
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("phuzz-helper-reader-{0}" -f [guid]::NewGuid().ToString("N"))
    $sourceRoot = Join-Path $tempRoot $PluginSlug
    $registry = Join-Path $OutputDir "helper_reader_registry.json"
    $analyzer = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\helper_request_reader_cli.py"
    try {
        New-Item -ItemType Directory -Path $sourceRoot -Force | Out-Null
        docker cp "${webContainerId}:/var/www/html/wp-content/plugins/$PluginSlug/." $sourceRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Could not copy plugin source for helper reader analysis."
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $registry) -Force | Out-Null
        python $analyzer --source-root $sourceRoot --display-root "/var/www/html/wp-content/plugins/$PluginSlug" --output $registry
        if ($LASTEXITCODE -ne 0) {
            throw "Helper reader analysis failed."
        }
        docker exec $webContainerId mkdir -p /shared-tmpfs/hook-coverage
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create the shared helper reader registry directory."
        }
        docker cp $registry "${webContainerId}:/shared-tmpfs/hook-coverage/helper_reader_registry.json"
        if ($LASTEXITCODE -ne 0) {
            throw "Could not publish helper reader registry to the web container."
        }
    } finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

function Assert-PathExists {
    param(
        [string]$Path,
        [string]$Hint
    )

    if (-not (Test-Path $Path)) {
        throw "Missing required file: $Path`n$Hint"
    }
}

function Wait-ForWebReady {
    param(
        [string]$Url,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                Write-Host "Web is ready: $Url"
                return
            }
        } catch {
            Start-Sleep -Seconds 5
            continue
        }

        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for $Url to return HTTP 200 within $TimeoutSeconds seconds."
}

function Invoke-RestRegistrationProbe {
    param([string]$BaseUrl)

    # A real REST index request fires rest_api_init, allowing plugins to register routes.
    foreach ($path in @('/wp-json/', '/?rest_route=/')) {
        try {
            $response = Invoke-WebRequest -Uri ($BaseUrl.TrimEnd('/') + $path) -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
            continue
        }
    }
    throw 'REST registration probe failed for both canonical and rest_route index URLs.'
}

function Export-LiveSeedSuggestions {
    param(
        [string]$ScriptRoot,
        [int]$WaitSeconds,
        [string[]]$ComposeArgs,
        [string]$PluginSlug,
        [string]$OutputDir
    )

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for seed export."
    }

    $coverageFileInContainer = "/shared-tmpfs/hook-coverage/total_coverage.json"
    $coverageSnapshot = Join-Path ([System.IO.Path]::GetTempPath()) "phuzz-live-total-coverage.json"
    $exportCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\export_cli.py"
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $snapshotReady = $false
    $pluginSourceTempRoot = $null

    try {
        Write-Host "Waiting for live hook coverage snapshot to export suggested seeds"
        while ((Get-Date) -lt $deadline) {
            try {
                $snapshot = docker exec $webContainerId sh -c "cat $coverageFileInContainer" 2>$null
                if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($snapshot)) {
                    $snapshot | Set-Content -Path $coverageSnapshot -Encoding UTF8
                    $snapshotReady = $true
                    break
                }
            } catch {
            }

            Start-Sleep -Seconds 5
        }

        if (-not $snapshotReady) {
            throw "Timed out waiting for live hook coverage snapshot at $coverageFileInContainer."
        }

        $sourceArgs = @()
        $pluginSourceTempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("phuzz-plugin-source-{0}" -f ([guid]::NewGuid().ToString("N")))
        $hostSourceRoot = Join-Path $pluginSourceTempRoot $PluginSlug
        New-Item -ItemType Directory -Path $hostSourceRoot -Force | Out-Null
        $unresolvedSourceReason = $null

        try {
            docker cp "${webContainerId}:/var/www/html/wp-content/plugins/$PluginSlug/." $hostSourceRoot
            if ($LASTEXITCODE -ne 0) {
                $unresolvedSourceReason = "source_copy_failed"
            } elseif (-not (Get-ChildItem -LiteralPath $hostSourceRoot -Recurse -Filter *.php -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
                $unresolvedSourceReason = "no_php_files"
            } else {
                $sourceArgs = @(
                    "--container-source-root", "/var/www/html/wp-content/plugins/$PluginSlug",
                    "--host-source-root", $hostSourceRoot,
                    "--source-root", $hostSourceRoot
                )
            }
        } catch {
            $unresolvedSourceReason = "source_copy_failed"
        }

        if ($unresolvedSourceReason) {
            Write-Warning "Plugin source unavailable for seed extraction: $unresolvedSourceReason"
            $sourceArgs = @("--unresolved-source-reason", $unresolvedSourceReason)
        }

        Write-Host "Exporting hook_gap_report.json and suggested_seeds.* to $outputDir"
        python $exportCli --coverage-file $coverageSnapshot --output-dir $outputDir @sourceArgs
    } finally {
        if ($pluginSourceTempRoot -and (Test-Path -LiteralPath $pluginSourceTempRoot)) {
            try {
                Remove-Item -LiteralPath $pluginSourceTempRoot -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning "Plugin source temp cleanup failed: $($_.Exception.Message)"
            }
        }
    }
}

function Convert-LiveSeedSuggestionsToConfigs {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string[]]$ComposeArgs,
        [string[]]$RequestArtifactsBefore,
        [string]$SeedOutputDir,
        [string]$OutputConfigDir,
        [bool]$WriteRuntimeDiscoverySummary
    )

    $suggestedSeeds = Join-Path $seedOutputDir "suggested_seeds.json"
    $summaryPath = Join-Path $seedOutputDir "generated_config_summary.json"
    $configCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\seed_to_config_cli.py"
    $runtimeArtifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("phuzz-runtime-artifacts-{0}" -f [guid]::NewGuid().ToString("N"))

    Assert-PathExists -Path $suggestedSeeds -Hint "Run hook seed export before converting seeds into PHUZZ configs."

    try {
        $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
        if ($webContainerId) {
            New-Item -ItemType Directory -Path $runtimeArtifactRoot -Force | Out-Null
            $previousErrorActionPreference = $ErrorActionPreference
            $copyExitCode = 1
            try {
                $ErrorActionPreference = 'Continue'
                docker cp "${webContainerId}:/shared-tmpfs/hook-coverage/requests/." $runtimeArtifactRoot 2>$null
                $copyExitCode = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            if ($copyExitCode -ne 0) {
                throw "Could not copy runtime request artifacts from web container."
            }
        }
        $artifacts = @(Get-ChildItem -LiteralPath $runtimeArtifactRoot -Filter *.json -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $RequestArtifactsBefore -notcontains $_.Name } |
            ForEach-Object { [ordered]@{ path = $_.FullName; request_id = $_.BaseName; context = 'bootstrap_or_probe'; expected_callback_id = ''; required = $true } })
        $manifestPath = Join-Path $runtimeArtifactRoot 'runtime_discovery_manifest.json'
        [ordered]@{ schema_version = 1; run_id = [guid]::NewGuid().ToString('N'); created_at = (Get-Date).ToUniversalTime().ToString('o'); plugin_slug = $PluginSlug; artifacts = $artifacts } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        if ($WriteRuntimeDiscoverySummary) {
            Write-RuntimeDiscoverySummary -ArtifactFiles @($artifacts | ForEach-Object { $_.path }) -OutputPath (Join-Path $seedOutputDir "runtime_discovery_summary.json") -PluginSlug $PluginSlug
        }
        Write-Host "Converting supported suggested seeds into PHUZZ configs"
        python $configCli `
            --suggested-seeds $suggestedSeeds `
            --output-config-dir $outputConfigDir `
            --summary $summaryPath `
            --runtime-discovery-manifest $manifestPath
    } finally {
        if (Test-Path -LiteralPath $runtimeArtifactRoot) {
            Remove-Item -LiteralPath $runtimeArtifactRoot -Recurse -Force
        }
    }
}

function Write-RuntimeDiscoverySummary {
    param(
        [string[]]$ArtifactFiles,
        [string]$OutputPath,
        [string]$PluginSlug
    )

    $discoveries = @()
    $readerHooks = @()
    foreach ($artifactFile in $ArtifactFiles) {
        try {
            $artifact = Get-Content -LiteralPath $artifactFile -Raw | ConvertFrom-Json
        } catch {
            continue
        }
        $discoveries += @($artifact.runtime_param_discoveries | Where-Object { $_ })
        $hooks = $artifact.debug.runtime_param_discovery.reader_hooks
        if ($hooks) {
            foreach ($property in $hooks.PSObject.Properties) {
                $readerHooks += [ordered]@{
                    symbol = $property.Name
                    status = $property.Value.status
                    reason = $property.Value.reason
                }
            }
        }
    }

    $summary = [ordered]@{
        schema_version = 1
        plugin_slug = $PluginSlug
        request_artifact_count = @($ArtifactFiles).Count
        discovery_count = @($discoveries).Count
        observed_reader_functions = @($discoveries | ForEach-Object { $_.reader_function } | Where-Object { $_ } | Sort-Object -Unique)
        discoveries = $discoveries
        reader_hooks = @($readerHooks | Sort-Object symbol, status, reason -Unique)
    }
    $summary | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    $ready = @($summary.reader_hooks | Where-Object { $_.status -in @('installed', 'already_installed') }).Count
    Write-Host ("Dynamic discovery: request_artifacts={0}, observations={1}, helpers_observed={2}, reader_hooks_ready={3}" -f $summary.request_artifact_count, $summary.discovery_count, @($summary.observed_reader_functions).Count, $ready)
}

function Write-DynamicConfigSummary {
    param([string]$OutputDir)

    $configSummary = Get-Content -LiteralPath (Join-Path $OutputDir "generated_config_summary.json") -Raw | ConvertFrom-Json
    $paramSummary = Get-Content -LiteralPath (Join-Path $OutputDir "generated_param_summary.json") -Raw | ConvertFrom-Json
    $provenance = @($paramSummary.configs | ForEach-Object { @($_.runtime_param_provenance | Where-Object { $_ }) })
    $added = @($provenance | Where-Object { $_.merge_action -eq 'added' }).Count
    $matched = @($provenance | Where-Object { $_.merge_action -eq 'matched_existing' }).Count
    $rejected = @($provenance | Where-Object { $_.merge_action -eq 'rejected' }).Count
    Write-Host ("Dynamic configs: generated={0}, fuzzing_ready={1}, runtime_added={2}, runtime_matched={3}, runtime_rejected={4}" -f @($configSummary.generated).Count, $paramSummary.summary.fuzzing_ready, $added, $matched, $rejected)
    return [pscustomobject]@{ GeneratedCount = @($configSummary.generated).Count }
}

function Write-DynamicReplaySummary {
    param([string]$OutputDir)

    $runSummaryPath = Join-Path $OutputDir "generated_config_run_summary.json"
    $validationPath = Join-Path $OutputDir "validation_result.json"
    if (-not (Test-Path -LiteralPath $runSummaryPath) -or -not (Test-Path -LiteralPath $validationPath)) {
        Write-Host "Dynamic E2E FAIL: replay report missing."
        return $false
    }
    $runSummary = Get-Content -LiteralPath $runSummaryPath -Raw | ConvertFrom-Json
    $validation = Get-Content -LiteralPath $validationPath -Raw | ConvertFrom-Json
    $total = @($validation.validations).Count
    $reached = @($validation.validations | Where-Object { $_.callback_reached }).Count
    $passed = $total -gt 0 -and $reached -eq $total
    Write-Host ("Dynamic replay: callback_reached={0}/{1}, process_failed={2}, runner_error={3}" -f $reached, $total, $runSummary.counts.process_failed, $runSummary.counts.runner_error)
    Write-Host ("Dynamic E2E {0}" -f $(if ($passed) { 'PASS' } else { 'FAIL' }))
    return $passed
}

function Clear-DynamicWorkflowArtifacts {
    param(
        [string]$OutputDir,
        [string]$ConfigDir
    )

    foreach ($path in @($OutputDir, $ConfigDir)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}

Push-Location $scriptRoot
$overridePath = $null
$previousComposeFile = $null
$dynamicComposeFileSet = $false
try {
    Write-Host "Using WordPress plugin: $PluginSlug"
    $isDynamic = $ParamDiscoveryMode -eq 'dynamic-helper'
    $seedOutputDir = if ($isDynamic) {
        Join-Path $scriptRoot "fuzzer\output\param-discovery\$PluginSlug\dynamic-helper"
    } else {
        Join-Path $scriptRoot "fuzzer\output\seed_generation"
    }
    $outputConfigDir = if ($isDynamic) {
        Join-Path $scriptRoot "fuzzer\configs\generated-param-discovery\$PluginSlug\dynamic-helper"
    } else {
        Join-Path $scriptRoot "fuzzer\configs\generated-config\$PluginSlug"
    }
    if ($isDynamic) {
        Clear-DynamicWorkflowArtifacts -OutputDir $seedOutputDir -ConfigDir $outputConfigDir
    }
    $overridePath = New-PluginOverrideFile -PluginSlug $PluginSlug -BootstrapConfigSlug $BootstrapConfigSlug -ParamDiscoveryMode $ParamDiscoveryMode
    $composeArgs = Get-ComposeArgs -OverridePath $overridePath

    Write-Host "Checking Docker availability"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("version")

    if ($PluginSlug -eq "show-all-comments-in-one-page") {
        Write-Host "Ensuring default plugin ZIP exists"
        if ($ForcePlugins) {
            & $pluginScript -Force
        } else {
            & $pluginScript
        }
    } else {
        Write-Host "Using local plugin ZIP for $PluginSlug"
        if ($ForcePlugins) {
            Write-Host "-ForcePlugins only applies to the default download script; selected plugin must exist locally."
        }
    }

    $requiredConfig = Join-Path $scriptRoot ("fuzzer\configs\{0}.json" -f $BootstrapConfigSlug.Replace("/", [System.IO.Path]::DirectorySeparatorChar))
    $requiredPlugin = Join-Path $scriptRoot "web\applications\wordpress\_plugins\$PluginSlug.zip"
    $requiredWpCli = Join-Path $scriptRoot "web\applications\wordpress\wp-cli.phar"

    Assert-PathExists -Path $requiredConfig -Hint "Choose an existing bootstrap config slug."
    Assert-PathExists -Path $requiredPlugin -Hint "Choose a plugin ZIP that exists in web\applications\wordpress\_plugins, or add $PluginSlug.zip there."
    Assert-PathExists -Path $requiredWpCli -Hint "The WordPress bootstrap artifact is missing from this checkout."

    Write-Host "Starting db and web containers"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build")

    $requestArtifactsBefore = @(Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("exec", "-T", "web", "sh", "-c", "find /shared-tmpfs/hook-coverage/requests -maxdepth 1 -type f -printf '%f\\n'") | Where-Object { $_ })
    Write-Host "Waiting for WordPress to answer with HTTP 200"
    Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds
    Invoke-RestRegistrationProbe -BaseUrl $webUrl

    if ($ParamDiscoveryMode -eq 'dynamic-helper') {
        Publish-HelperReaderRegistry -ScriptRoot $scriptRoot -ComposeArgs $composeArgs -PluginSlug $PluginSlug -OutputDir $seedOutputDir
    }

    Write-Host "Starting fuzzer container"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $fuzzerService, "--build")

    Export-LiveSeedSuggestions -ScriptRoot $scriptRoot -WaitSeconds $SeedWaitSeconds -ComposeArgs $composeArgs -PluginSlug $PluginSlug -OutputDir $seedOutputDir
    Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot -PluginSlug $PluginSlug -ComposeArgs $composeArgs -RequestArtifactsBefore $requestArtifactsBefore -SeedOutputDir $seedOutputDir -OutputConfigDir $outputConfigDir -WriteRuntimeDiscoverySummary $false

    if ($RunGeneratedConfigs) {
        $generatedConfigSummary = Join-Path $seedOutputDir "generated_config_summary.json"
        $generatedRunSummary = Join-Path $seedOutputDir "generated_config_run_summary.json"
        $generatedConfigRunner = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\generated_config_runner.py"

        if ($isDynamic) {
            $previousComposeFile = $env:COMPOSE_FILE
            $env:COMPOSE_FILE = "docker-compose.yml$([System.IO.Path]::PathSeparator)$overridePath"
            $dynamicComposeFileSet = $true
        }

        Write-Host "Stopping default fuzzer before generated config batch"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("stop", "--timeout", "30", $fuzzerService)

        if ($isDynamic) {
            $initialConfigSummary = Get-Content -LiteralPath (Join-Path $seedOutputDir "generated_config_summary.json") -Raw | ConvertFrom-Json
            if (@($initialConfigSummary.generated).Count -eq 0) {
                throw "Dynamic E2E failed: no generated configs. See $seedOutputDir"
            }

            $discoveryRunSummary = Join-Path $seedOutputDir "dynamic_discovery_run_summary.json"
            $discoveryValidation = Join-Path $seedOutputDir "dynamic_discovery_validation_result.json"
            Write-Host "Running dynamic discovery replay before config merge"
            python $generatedConfigRunner `
                --generated-config-summary $generatedConfigSummary `
                --output-file $discoveryRunSummary `
                --timeout-seconds $GeneratedConfigTimeoutSeconds `
                --service $fuzzerService
            $discoveryValidationSource = Join-Path $seedOutputDir "validation_result.json"
            if (Test-Path -LiteralPath $discoveryValidationSource) {
                Move-Item -LiteralPath $discoveryValidationSource -Destination $discoveryValidation -Force
            }

            Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot -PluginSlug $PluginSlug -ComposeArgs $composeArgs -RequestArtifactsBefore $requestArtifactsBefore -SeedOutputDir $seedOutputDir -OutputConfigDir $outputConfigDir -WriteRuntimeDiscoverySummary $true
            $dynamicConfigSummary = Write-DynamicConfigSummary -OutputDir $seedOutputDir
            if ($dynamicConfigSummary.GeneratedCount -eq 0) {
                throw "Dynamic E2E failed: no generated configs after discovery. See $seedOutputDir"
            }
        }

        Write-Host "Running generated hook configs sequentially"
        python $generatedConfigRunner `
            --generated-config-summary $generatedConfigSummary `
            --output-file $generatedRunSummary `
            --timeout-seconds $GeneratedConfigTimeoutSeconds `
            --service $fuzzerService
        $generatedConfigExitCode = $LASTEXITCODE
        $dynamicE2EPassed = $true
        if ($isDynamic) {
            $dynamicE2EPassed = Write-DynamicReplaySummary -OutputDir $seedOutputDir
        }
        if ($generatedConfigExitCode -ne 0 -or -not $dynamicE2EPassed) {
            throw "Generated hook config batch failed. See $generatedRunSummary"
        }

        Write-Host "Generated config run summary: $generatedRunSummary"
    } elseif ($NoFollowLogs) {
        Write-Host "PHUZZ started. To follow logs later, run:"
        Write-Host "  docker compose logs -f $fuzzerService"
        Write-Host "Suggested seed artifacts:"
        Write-Host "  $scriptRoot\fuzzer\output\seed_generation"
        Write-Host "Generated hook config artifacts:"
        Write-Host "  $scriptRoot\fuzzer\configs\generated-config\$PluginSlug"
    } else {
        Write-Host "Following fuzzer logs. Press Ctrl+C to stop following without stopping containers."
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("logs", "-f", $fuzzerService)
    }
} finally {
    if ($dynamicComposeFileSet) {
        if ($null -eq $previousComposeFile) {
            Remove-Item Env:COMPOSE_FILE -ErrorAction SilentlyContinue
        } else {
            $env:COMPOSE_FILE = $previousComposeFile
        }
    }
    if ($overridePath -and (Test-Path -LiteralPath $overridePath)) {
        Remove-Item -LiteralPath $overridePath -Force
    }
    Pop-Location
}
