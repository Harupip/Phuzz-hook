param(
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug = "show-all-comments-in-one-page",
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [switch]$RunGeneratedConfigs,
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [ValidateRange(1, 86400)]
    [int]$GeneratedConfigTimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginScript = Join-Path $scriptRoot "web\applications\wordpress\_plugins\download-plugins.ps1"
$fuzzerService = "fuzzer-wordpress-plugin"
$webUrl = "http://localhost:8080/"

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
    param([string]$PluginSlug)

    $path = Join-Path $env:TEMP ("phuzz-{0}.override.yml" -f $PluginSlug)
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/"
        "      WP_TARGET_PLUGIN: $PluginSlug"
        "  ${fuzzerService}:"
        "    environment:"
        "      FUZZER_CONFIG: wordpress/$PluginSlug"
    )
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
        [string]$PluginSlug
    )

    $webContainerId = (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for seed export."
    }

    $coverageFileInContainer = "/shared-tmpfs/hook-coverage/total_coverage.json"
    $coverageSnapshot = Join-Path ([System.IO.Path]::GetTempPath()) "phuzz-live-total-coverage.json"
    $outputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
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
            Remove-Item -LiteralPath $pluginSourceTempRoot -Recurse -Force
        }
    }
}

function Convert-LiveSeedSuggestionsToConfigs {
    param(
        [string]$ScriptRoot
    )

    $seedOutputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    $suggestedSeeds = Join-Path $seedOutputDir "suggested_seeds.json"
    $outputConfigDir = Join-Path $ScriptRoot "fuzzer\configs\generated-hooks"
    $summaryPath = Join-Path $seedOutputDir "generated_config_summary.json"
    $configCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\seed_to_config_cli.py"

    Assert-PathExists -Path $suggestedSeeds -Hint "Run hook seed export before converting seeds into PHUZZ configs."

    Write-Host "Converting supported suggested seeds into PHUZZ configs"
    python $configCli `
        --suggested-seeds $suggestedSeeds `
        --output-config-dir $outputConfigDir `
        --summary $summaryPath
}

Push-Location $scriptRoot
$overridePath = $null
try {
    Write-Host "Using WordPress plugin: $PluginSlug"
    $overridePath = New-PluginOverrideFile -PluginSlug $PluginSlug
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

    $requiredConfig = Join-Path $scriptRoot "fuzzer\configs\wordpress\$PluginSlug.json"
    $requiredPlugin = Join-Path $scriptRoot "web\applications\wordpress\_plugins\$PluginSlug.zip"
    $requiredWpCli = Join-Path $scriptRoot "web\applications\wordpress\wp-cli.phar"

    Assert-PathExists -Path $requiredConfig -Hint "Choose a plugin with a matching fuzzer\configs\wordpress\<slug>.json file."
    Assert-PathExists -Path $requiredPlugin -Hint "Choose a plugin ZIP that exists in web\applications\wordpress\_plugins, or add $PluginSlug.zip there."
    Assert-PathExists -Path $requiredWpCli -Hint "The WordPress bootstrap artifact is missing from this checkout."

    Write-Host "Starting db and web containers"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build")

    Write-Host "Waiting for WordPress to answer with HTTP 200"
    Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

    Write-Host "Starting fuzzer container"
    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $fuzzerService, "--build")

    Export-LiveSeedSuggestions -ScriptRoot $scriptRoot -WaitSeconds $SeedWaitSeconds -ComposeArgs $composeArgs -PluginSlug $PluginSlug
    Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot

    if ($RunGeneratedConfigs) {
        $seedOutputDir = Join-Path $scriptRoot "fuzzer\output\seed_generation"
        $generatedConfigSummary = Join-Path $seedOutputDir "generated_config_summary.json"
        $generatedRunSummary = Join-Path $seedOutputDir "generated_config_run_summary.json"
        $generatedConfigRunner = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\generated_config_runner.py"

        Write-Host "Stopping default fuzzer before generated config batch"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("stop", "--timeout", "30", $fuzzerService)

        Write-Host "Running generated hook configs sequentially"
        python $generatedConfigRunner `
            --generated-config-summary $generatedConfigSummary `
            --output-file $generatedRunSummary `
            --timeout-seconds $GeneratedConfigTimeoutSeconds `
            --service $fuzzerService
        if ($LASTEXITCODE -ne 0) {
            throw "Generated hook config batch failed. See $generatedRunSummary"
        }

        Write-Host "Generated config run summary: $generatedRunSummary"
    } elseif ($NoFollowLogs) {
        Write-Host "PHUZZ started. To follow logs later, run:"
        Write-Host "  docker compose logs -f $fuzzerService"
        Write-Host "Suggested seed artifacts:"
        Write-Host "  $scriptRoot\fuzzer\output\seed_generation"
        Write-Host "Generated hook config artifacts:"
        Write-Host "  $scriptRoot\fuzzer\configs\generated-hooks"
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
