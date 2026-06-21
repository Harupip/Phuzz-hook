param(
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [int]$WebTimeoutSeconds = 240,
    [int]$SeedWaitSeconds = 45
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginScript = Join-Path $scriptRoot "web\applications\wordpress\_plugins\download-plugins.ps1"
$fuzzerService = "fuzzer-wordpress-plugin"
$webUrl = "http://localhost:8080/"

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
        [int]$WaitSeconds
    )

    $webContainerId = (docker compose ps -q web).Trim()
    if (-not $webContainerId) {
        throw "Could not resolve the running web container for seed export."
    }

    $coverageFileInContainer = "/shared-tmpfs/hook-coverage/total_coverage.json"
    $coverageSnapshot = Join-Path ([System.IO.Path]::GetTempPath()) "phuzz-live-total-coverage.json"
    $outputDir = Join-Path $ScriptRoot "fuzzer\output\seed_generation"
    $exportCli = Join-Path $ScriptRoot "fuzzer\hook_energy\seed_generation\export_cli.py"
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $snapshotReady = $false

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

    Write-Host "Exporting hook_gap_report.json and suggested_seeds.* to $outputDir"
    python $exportCli --coverage-file $coverageSnapshot --output-dir $outputDir
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

    Write-Host "Converting unauth-capable suggested seeds into PHUZZ configs"
    python $configCli `
        --suggested-seeds $suggestedSeeds `
        --output-config-dir $outputConfigDir `
        --summary $summaryPath
}

Push-Location $scriptRoot
try {
    Write-Host "Checking Docker availability"
    docker compose version | Out-Null

    Write-Host "Downloading required plugin ZIPs"
    if ($ForcePlugins) {
        & $pluginScript -Force
    } else {
        & $pluginScript
    }

    $requiredConfig = Join-Path $scriptRoot "fuzzer\configs\wordpress\show-all-comments-in-one-page.json"
    $requiredPlugin = Join-Path $scriptRoot "web\applications\wordpress\_plugins\show-all-comments-in-one-page.zip"
    $requiredWpCli = Join-Path $scriptRoot "web\applications\wordpress\wp-cli.phar"

    Assert-PathExists -Path $requiredConfig -Hint "This working tree must already contain the PHUZZ config JSON."
    Assert-PathExists -Path $requiredPlugin -Hint "Run the plugin download step again or check network access."
    Assert-PathExists -Path $requiredWpCli -Hint "The WordPress bootstrap artifact is missing from this checkout."

    Write-Host "Starting db and web containers"
    docker compose up -d db web --build

    Write-Host "Waiting for WordPress to answer with HTTP 200"
    Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

    Write-Host "Starting fuzzer container"
    docker compose up -d $fuzzerService --build

    Export-LiveSeedSuggestions -ScriptRoot $scriptRoot -WaitSeconds $SeedWaitSeconds
    Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot

    if ($NoFollowLogs) {
        Write-Host "PHUZZ started. To follow logs later, run:"
        Write-Host "  docker compose logs -f $fuzzerService"
        Write-Host "Suggested seed artifacts:"
        Write-Host "  $scriptRoot\fuzzer\output\seed_generation"
        Write-Host "Generated hook config artifacts:"
        Write-Host "  $scriptRoot\fuzzer\configs\generated-hooks"
    } else {
        Write-Host "Following fuzzer logs. Press Ctrl+C to stop following without stopping containers."
        docker compose logs -f $fuzzerService
    }
} finally {
    Pop-Location
}
