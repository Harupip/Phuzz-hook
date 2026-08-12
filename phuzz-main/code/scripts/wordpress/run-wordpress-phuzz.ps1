param(
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug = "show-all-comments-in-one-page",
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [switch]$RunGeneratedConfigs,
    [switch]$UseEntrypointPipeline,
    [switch]$UseZendDiscovery,
    [ValidatePattern('^[a-zA-Z0-9_./-]+$')]
    [string]$BootstrapConfigSlug = "",
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [ValidateRange(1, 30)]
    [int]$GeneratedConfigTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginScript = Join-Path $scriptRoot "web\applications\wordpress\_plugins\download-plugins.ps1"
$fuzzerService = "fuzzer-wordpress-plugin"
$webUrl = "http://localhost:8080/"

if ($UseEntrypointPipeline -and -not $RunGeneratedConfigs) {
    throw "-UseEntrypointPipeline requires -RunGeneratedConfigs."
}
if ($UseZendDiscovery -and -not $RunGeneratedConfigs) {
    throw "-UseZendDiscovery requires -RunGeneratedConfigs."
}
if ($UseZendDiscovery -and $UseEntrypointPipeline) {
    throw "-UseZendDiscovery uses the legacy generated flow and cannot be combined with -UseEntrypointPipeline."
}

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
        [string]$LegacyRunId = "",
        [switch]$UseZendDiscovery
    )

    $path = Join-Path $env:TEMP ("phuzz-{0}.override.yml" -f $PluginSlug)
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/"
        "      WP_TARGET_PLUGIN: $PluginSlug"
    )
    if ($UseZendDiscovery) {
        $content += @(
            "    build:"
            "      context: ../.."
            "      dockerfile: phuzz-main/code/web/Dockerfile.zend"
            "    volumes:"
            "      - ./web/applications:/applications/"
            "      - shared-tmpfs:/shared-tmpfs"
            "      - shared-tmpfs:/shared"
        )
    }
    $content += @(
        "  ${fuzzerService}:"
        "    environment:"
        "      FUZZER_CONFIG: $BootstrapConfigSlug"
    )
    if ($LegacyRunId) {
        $content += "      HOOKPHUZZ_LEGACY_RUN_ID: $LegacyRunId"
    }
    Set-Content -LiteralPath $path -Value $content -Encoding ASCII
    return $path
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

function Export-LiveSeedSuggestions {
    param(
        [string]$ScriptRoot,
        [int]$WaitSeconds,
        [string[]]$ComposeArgs,
        [string]$PluginSlug,
        [switch]$UseEntrypointPipeline,
        [switch]$RuntimeParametersOnly
    )

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for seed export."
    }

    $coverageFileInContainer = "/shared-tmpfs/hook-coverage/total_coverage.json"
    $coverageSnapshot = Join-Path ([System.IO.Path]::GetTempPath()) "phuzz-live-total-coverage.json"
    $outputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    $exportCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\export_cli.py"
    $pipelineCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\pipeline_cli.py"
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
                    $snapshotOutput = Join-Path $outputDir "runtime_coverage_snapshot.json"
                    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                    $snapshot | Set-Content -Path $snapshotOutput -Encoding UTF8
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
        $unresolvedSourceReason = $null

        if (-not $RuntimeParametersOnly) {
            New-Item -ItemType Directory -Path $hostSourceRoot -Force | Out-Null
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
        }

        if ($UseEntrypointPipeline) {
            $outputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
            Write-Host "Running entrypoint pipeline into $outputDir"
            python $pipelineCli `
                --coverage-file $coverageSnapshot `
                --plugin-slug $PluginSlug `
                --output-dir $outputDir `
                --output-config-dir $outputConfigDir `
                --minimal-artifacts `
                @sourceArgs
        } else {
            Write-Host "Exporting hook_gap_report.json and suggested_seeds.* to $outputDir"
            $exportArgs = @($exportCli, "--coverage-file", $coverageSnapshot, "--output-dir", $outputDir)
            if ($RuntimeParametersOnly) {
                $exportArgs += "--runtime-parameters-only"
            } else {
                $exportArgs += $sourceArgs
            }
            python @exportArgs
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Seed export failed."
        }
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
        [string]$OutputConfigDir = "",
        [string]$SummaryPath = "",
        [switch]$ReplayOnly
    )

    $seedOutputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    $suggestedSeeds = Join-Path $seedOutputDir "suggested_seeds.json"
    if (-not $OutputConfigDir) {
        $OutputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
    }
    if (-not $SummaryPath) {
        $SummaryPath = Join-Path $seedOutputDir "generated_config_summary.json"
    }
    $configCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\seed_to_config_cli.py"

    Assert-PathExists -Path $suggestedSeeds -Hint "Run hook seed export before converting seeds into PHUZZ configs."

    Write-Host "Converting supported suggested seeds into PHUZZ configs"
    $configArgs = @(
        $configCli,
        "--suggested-seeds", $suggestedSeeds,
        "--output-config-dir", $OutputConfigDir,
        "--summary", $SummaryPath
    )
    if ($ReplayOnly) {
        $configArgs += "--replay-only"
    }
    python @configArgs
}

function Write-EntrypointPluginProofFile {
    param(
        [string]$SeedOutputDir,
        [string]$PluginSlug,
        [string]$RunnerLog
    )

    $pipelinePath = Join-Path $SeedOutputDir "entrypoint_pipeline_summary.json"
    $configPath = Join-Path $SeedOutputDir "generated_config_summary.json"
    $runPath = Join-Path $SeedOutputDir "generated_config_run_summary.json"
    if (-not (Test-Path -LiteralPath $pipelinePath)) {
        return
    }

    $proofDir = Join-Path $SeedOutputDir "entrypoint-proof"
    New-Item -ItemType Directory -Path $proofDir -Force | Out-Null
    $proofPath = Join-Path $proofDir "PLUGIN_GENERATION_PROOF.md"
    $pipeline = Get-Content -LiteralPath $pipelinePath -Raw | ConvertFrom-Json
    $run = $null
    if (Test-Path -LiteralPath $runPath) {
        $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Entrypoint generated plugin proof")
    $lines.Add("")
    $lines.Add("Plugin: ``$PluginSlug``")
    $lines.Add("")
    $lines.Add("## Counters")
    $lines.Add("")
    $lines.Add(("- registered: {0}" -f $pipeline.summary.registered))
    $lines.Add(("- direct_http_candidates: {0}" -f $pipeline.summary.direct_http_candidates))
    $lines.Add(("- generated: {0}" -f $pipeline.summary.generated))
    $lines.Add(("- ambiguous_http_method: {0}" -f $pipeline.summary.ambiguous_http_method))
    $lines.Add("")
    $lines.Add("## Generated configs")
    $lines.Add("")

    foreach ($entry in @($pipeline.entrypoints | Where-Object { $_.config_status -eq "generated" })) {
        $lines.Add(("### [{0}] {1}" -f $entry.method, $entry.hook_name))
        $lines.Add("")
        $lines.Add(("- callback: ``{0}``" -f $entry.callback_repr))
        $lines.Add(("- action: ``{0}``" -f $entry.action))
        foreach ($param in @($entry.parameters)) {
            if ($param.name) {
                $lines.Add(("- param: ``{0}`` from ``{1}`` as ``{2}``" -f $param.name, $param.source, $param.location))
            }
        }
        $lines.Add(("- config_slug: ``{0}``" -f $entry.config_slug))
        $lines.Add(("- config_path: ``{0}``" -f $entry.config_path))
        $lines.Add("")
    }

    if ($run) {
        $lines.Add("## Replay")
        $lines.Add("")
        $lines.Add(("- callback_reached: {0}/{1}" -f $run.counts.callback_reached, $run.counts.total))
        foreach ($row in @($run.runs)) {
            if ($row.matched_artifact) {
                $lines.Add(("- matched_artifact: ``{0}``" -f $row.matched_artifact))
            }
        }
        $lines.Add("")
    }

    $lines.Add("## Source artifacts")
    $lines.Add("")
    $lines.Add(("- runtime coverage snapshot: ``{0}``" -f (Join-Path $SeedOutputDir "runtime_coverage_snapshot.json")))
    $lines.Add(("- pipeline summary: ``{0}``" -f $pipelinePath))
    $lines.Add(("- config summary: ``{0}``" -f $configPath))
    $lines.Add(("- replay summary: ``{0}``" -f $runPath))
    if ($RunnerLog) {
        $lines.Add(("- replay log: ``{0}``" -f $RunnerLog))
    }

    $lines | Set-Content -LiteralPath $proofPath -Encoding UTF8
    Write-Host "Entrypoint plugin proof file: $proofPath"
}

function Copy-GeneratedRequestArtifacts {
    param(
        [string[]]$ComposeArgs,
        [string]$RunSummaryPath,
        [string]$OutputDir
    )

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $summary = Get-Content -LiteralPath $RunSummaryPath -Raw | ConvertFrom-Json
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach ($row in @($summary.runs)) {
        if ($row.matched_artifact) {
            [void]$names.Add([string]$row.matched_artifact)
        }
        foreach ($name in @($row.request_artifacts)) {
            if ($name) {
                [void]$names.Add([string]$name)
            }
        }
    }
    foreach ($name in $names) {
        if ([System.IO.Path]::GetFileName($name) -ne $name) {
            throw "Invalid generated request artifact name: $name"
        }
        $target = Join-Path $OutputDir $name
        & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat "/shared-tmpfs/hook-coverage/requests/$name" |
            Set-Content -LiteralPath $target -Encoding UTF8
        if ($LASTEXITCODE -ne 0) {
            throw "Could not copy generated request artifact: $name"
        }
    }
}

function Copy-ZendOpcodeArtifacts {
    param(
        [string[]]$ComposeArgs,
        [string]$RunSummaryPath,
        [string]$OutputDir
    )

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $summary = Get-Content -LiteralPath $RunSummaryPath -Raw | ConvertFrom-Json
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach ($row in @($summary.runs)) {
        if ($row.matched_artifact) {
            [void]$names.Add([string]$row.matched_artifact)
        }
    }
    foreach ($name in $names) {
        if ([System.IO.Path]::GetFileName($name) -ne $name) {
            throw "Invalid Zend opcode artifact name: $name"
        }
        $target = Join-Path $OutputDir $name
        & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web cat "/shared/opcode-events/$name" |
            Set-Content -LiteralPath $target -Encoding UTF8
        if ($LASTEXITCODE -ne 0) {
            throw "Could not copy Zend opcode artifact: $name"
        }
    }
}

function Initialize-ZendCallbackRegistry {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string]$SeedOutputDir,
        [string]$LegacyRunId,
        [string[]]$ComposeArgs
    )

    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $registryPath = Join-Path $bridgeWorkDir "phase9-callback-registry.json"
    $coverageSnapshot = Join-Path $SeedOutputDir "runtime_coverage_snapshot.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_bridge_cli.py"

    python $bridgeCli `
        --operation prepare-registry `
        --registry $coverageSnapshot `
        --plugin-slug $PluginSlug `
        --callback-registry-output $registryPath
    if ($LASTEXITCODE -ne 0) {
        throw "Zend callback registry preparation failed."
    }

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for Zend registry copy."
    }
    docker exec $webContainerId sh -lc "mkdir -p /shared/opcode-events && chown www-data:www-data /shared/opcode-events"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not prepare /shared/opcode-events."
    }
    docker cp $registryPath "${webContainerId}:/shared/phase9-callback-registry.json"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy Zend callback registry into web container."
    }
}

function Invoke-ZendDiscoveryBridge {
    param(
        [string]$ScriptRoot,
        [string]$PluginSlug,
        [string]$LegacyRunId,
        [string]$SeedOutputDir,
        [string]$Pass1RunSummary,
        [string[]]$ComposeArgs
    )

    $pluginZip = Join-Path $ScriptRoot "web\applications\wordpress\_plugins\$PluginSlug.zip"
    $rawSuggestedSeeds = Join-Path $SeedOutputDir "suggested_seeds.json"
    $registry = Join-Path $SeedOutputDir "runtime_coverage_snapshot.json"
    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $logsDir = Join-Path $bridgeWorkDir "logs"
    $pass1ArtifactsDir = Join-Path $logsDir "pass1-uopz"
    $zendEventsDir = Join-Path $logsDir "pass1-zend"
    $zendOutputRoot = Join-Path $ScriptRoot "fuzzer\output\zend-discovery"
    $mergedSuggestedSeeds = Join-Path $SeedOutputDir "zend_merged_suggested_seeds.json"
    $outputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-config\$PluginSlug"
    $finalConfigSummary = Join-Path $SeedOutputDir "generated_config_summary.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_bridge_cli.py"

    Copy-GeneratedRequestArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass1RunSummary -OutputDir $pass1ArtifactsDir
    Copy-ZendOpcodeArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass1RunSummary -OutputDir $zendEventsDir

    Write-Host "Running offline Zend enrichment bridge"
    python $bridgeCli `
        --plugin-zip $pluginZip `
        --plugin-slug $PluginSlug `
        --legacy-run-id $LegacyRunId `
        --registry $registry `
        --raw-suggested-seeds $rawSuggestedSeeds `
        --pass1-run-summary $Pass1RunSummary `
        --pass1-artifacts-dir $pass1ArtifactsDir `
        --zend-events-dir $zendEventsDir `
        --zend-output-root $zendOutputRoot `
        --merged-suggested-seeds $mergedSuggestedSeeds `
        --output-config-dir $outputConfigDir `
        --generated-config-summary $finalConfigSummary
    if ($LASTEXITCODE -ne 0) {
        throw "Zend enrichment bridge failed."
    }

    $zendEnrichedSeeds = Join-Path (Join-Path $zendOutputRoot $LegacyRunId) "zend_enriched_seeds.json"
    Write-Host "Zend enriched seeds: $zendEnrichedSeeds"
    Write-Host "Zend merged suggested seeds: $mergedSuggestedSeeds"
}

function Invoke-ZendPass2Verification {
    param(
        [string]$ScriptRoot,
        [string]$LegacyRunId,
        [string]$SeedOutputDir,
        [string]$Pass2RunSummary,
        [string[]]$ComposeArgs
    )

    $bridgeWorkDir = Join-Path (Join-Path $SeedOutputDir "zend-bridge") $LegacyRunId
    $logsDir = Join-Path $bridgeWorkDir "logs"
    $pass2ArtifactsDir = Join-Path $logsDir "pass2-uopz"
    $pass2ZendEventsDir = Join-Path $logsDir "pass2-zend"
    $mergedSuggestedSeeds = Join-Path $SeedOutputDir "zend_merged_suggested_seeds.json"
    $bridgeCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\zend_bridge_cli.py"

    Copy-GeneratedRequestArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass2RunSummary -OutputDir $pass2ArtifactsDir
    Copy-ZendOpcodeArtifacts -ComposeArgs $ComposeArgs -RunSummaryPath $Pass2RunSummary -OutputDir $pass2ZendEventsDir

    python $bridgeCli `
        --operation verify-pass2 `
        --pass2-run-summary $Pass2RunSummary `
        --merged-suggested-seeds $mergedSuggestedSeeds `
        --zend-events-dir $pass2ZendEventsDir
    if ($LASTEXITCODE -ne 0) {
        throw "Zend Pass 2 runtime verification failed. See $Pass2RunSummary"
    }
}

Push-Location $scriptRoot
$overridePath = $null
$legacyRunId = ""
if ($UseZendDiscovery) {
    $legacyRunId = "legacy-" + (Get-Date -Format "yyyyMMddTHHmmssZ") + "-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
}
try {
    Write-Host "Using WordPress plugin: $PluginSlug"
    $overridePath = New-PluginOverrideFile -PluginSlug $PluginSlug -BootstrapConfigSlug $BootstrapConfigSlug -LegacyRunId $legacyRunId -UseZendDiscovery:$UseZendDiscovery
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

    Write-Host "Waiting for WordPress to answer with HTTP 200"
    Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

    Write-Host "Starting fuzzer container"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $fuzzerService, "--build")

    Export-LiveSeedSuggestions -ScriptRoot $scriptRoot -WaitSeconds $SeedWaitSeconds -ComposeArgs $composeArgs -PluginSlug $PluginSlug -UseEntrypointPipeline:$UseEntrypointPipeline -RuntimeParametersOnly:$UseZendDiscovery
    if (-not $UseEntrypointPipeline) {
        Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot -PluginSlug $PluginSlug
    }

    if ($RunGeneratedConfigs) {
        $seedOutputDir = Join-Path $scriptRoot "fuzzer\output\seed_generation"
        $generatedConfigSummary = Join-Path $seedOutputDir "generated_config_summary.json"
        $generatedRunSummary = Join-Path $seedOutputDir "generated_config_run_summary.json"
        if ($UseZendDiscovery) {
            $bridgeWorkDir = Join-Path (Join-Path $seedOutputDir "zend-bridge") $legacyRunId
            $pass1ConfigDir = Join-Path $bridgeWorkDir "pass1-configs"
            $generatedConfigSummary = Join-Path $bridgeWorkDir "pass1-generated_config_summary.json"
            $generatedRunSummary = Join-Path $bridgeWorkDir "pass1-generated_config_run_summary.json"
            Initialize-ZendCallbackRegistry `
                -ScriptRoot $scriptRoot `
                -PluginSlug $PluginSlug `
                -SeedOutputDir $seedOutputDir `
                -LegacyRunId $legacyRunId `
                -ComposeArgs $composeArgs
            Convert-LiveSeedSuggestionsToConfigs `
                -ScriptRoot $scriptRoot `
                -PluginSlug $PluginSlug `
                -OutputConfigDir $pass1ConfigDir `
                -SummaryPath $generatedConfigSummary `
                -ReplayOnly
        }
        $generatedConfigRunner = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\generated_config_runner.py"
        $generatedRunnerLog = $null

        Write-Host "Stopping default fuzzer before generated config batch"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("stop", "--timeout", "30", $fuzzerService)

        Write-Host "Running generated hook configs sequentially"
        if ($UseEntrypointPipeline) {
            $generatedLogDir = Join-Path $seedOutputDir "entrypoint-proof\logs"
            New-Item -ItemType Directory -Path $generatedLogDir -Force | Out-Null
            $generatedRunnerLog = Join-Path $generatedLogDir "generated_config_runner.log"
            $generatedRunnerStdout = Join-Path $generatedLogDir "generated_config_runner.stdout.log"
            $generatedRunnerStderr = Join-Path $generatedLogDir "generated_config_runner.stderr.log"
            $generatedArgs = @(
                $generatedConfigRunner,
                "--generated-config-summary", $generatedConfigSummary,
                "--output-file", $generatedRunSummary,
                "--timeout-seconds", $GeneratedConfigTimeoutSeconds,
                "--service", $fuzzerService
            )
            if ($legacyRunId) {
                $generatedArgs += @("--legacy-run-id", $legacyRunId)
            }
            $generatedProcess = Start-Process `
                -FilePath "python" `
                -ArgumentList $generatedArgs `
                -Wait `
                -PassThru `
                -WindowStyle Hidden `
                -RedirectStandardOutput $generatedRunnerStdout `
                -RedirectStandardError $generatedRunnerStderr
            $generatedExitCode = $generatedProcess.ExitCode
            Get-Content -LiteralPath $generatedRunnerStdout, $generatedRunnerStderr -ErrorAction SilentlyContinue |
                Set-Content -LiteralPath $generatedRunnerLog -Encoding UTF8
        } else {
            $generatedArgs = @(
                $generatedConfigRunner,
                "--generated-config-summary", $generatedConfigSummary,
                "--output-file", $generatedRunSummary,
                "--timeout-seconds", "$GeneratedConfigTimeoutSeconds",
                "--service", $fuzzerService
            )
            if ($legacyRunId) {
                $generatedArgs += @("--legacy-run-id", $legacyRunId)
            }
            python @generatedArgs
            $generatedExitCode = $LASTEXITCODE
        }
        if ($UseEntrypointPipeline) {
            Write-EntrypointPluginProofFile -SeedOutputDir $seedOutputDir -PluginSlug $PluginSlug -RunnerLog $generatedRunnerLog
        }
        if ($generatedExitCode -ne 0) {
            throw "Generated hook config batch failed. See $generatedRunSummary"
        }

        if ($UseZendDiscovery) {
            Invoke-ZendDiscoveryBridge `
                -ScriptRoot $scriptRoot `
                -PluginSlug $PluginSlug `
                -LegacyRunId $legacyRunId `
                -SeedOutputDir $seedOutputDir `
                -Pass1RunSummary $generatedRunSummary `
                -ComposeArgs $composeArgs

            $generatedConfigSummary = Join-Path $seedOutputDir "generated_config_summary.json"
            $generatedRunSummary = Join-Path $seedOutputDir "pass2-generated_config_run_summary.json"
            python $generatedConfigRunner `
                --generated-config-summary $generatedConfigSummary `
                --output-file $generatedRunSummary `
                --timeout-seconds $GeneratedConfigTimeoutSeconds `
                --service $fuzzerService `
                --legacy-run-id $legacyRunId
            $generatedExitCode = $LASTEXITCODE
            if ($generatedExitCode -ne 0) {
                throw "Generated hook config Pass 2 failed. See $generatedRunSummary"
            }
            Invoke-ZendPass2Verification `
                -ScriptRoot $scriptRoot `
                -LegacyRunId $legacyRunId `
                -SeedOutputDir $seedOutputDir `
                -Pass2RunSummary $generatedRunSummary `
                -ComposeArgs $composeArgs
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
    if ($overridePath -and (Test-Path -LiteralPath $overridePath)) {
        Remove-Item -LiteralPath $overridePath -Force
    }
    Pop-Location
}
