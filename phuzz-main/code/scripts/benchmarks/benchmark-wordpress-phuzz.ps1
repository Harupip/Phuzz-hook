param(
    [int]$RunsPerMode = 5,
    [int]$RunMinutes = 30,
    [int]$RunHours = 0,
    [string[]]$Modes = @("PHUZZ_RAW", "PHUZZ_TRACE", "HOOK_TRACE"),
    [Alias("Plugin")]
    [string[]]$Plugins = @(
        "photo-gallery",
        "crm-perks-forms",
        "seo-local-rank",
        "totop-link",
        "webp-converter-for-media"
    ),
    [string]$OutputRoot = "fuzzer\output\benchmarks",
    [int]$BucketMinutes = 5,
    [int]$TraceMinutes = 20,
    [int]$FastSeedLimit = 5,
    [int]$WebTimeoutSeconds = 240,
    [int]$FirstRequestTimeoutSeconds = 180,
    [switch]$TearDownAfterBenchmark
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$localFuzzerOutputDir = Join-Path $scriptRoot "fuzzer\output\fuzzer-1"
$summaryCliPath = Join-Path $scriptRoot "fuzzer\benchmarking\summary.py"
$seedExportCliPath = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\export_cli.py"
$pluginZipRoot = Join-Path $scriptRoot "web\applications\wordpress\_plugins"
$webUrl = "http://localhost:8080/"
$fuzzerService = "fuzzer-wordpress-plugin"
$composeBaseArgs = @("docker", "compose", "-f", "docker-compose.yml")
$totalRunMinutes = if ($RunHours -gt 0) { $RunHours * 60 } else { $RunMinutes }
if ($totalRunMinutes -le 0) {
    throw "Run duration must be positive. Use -RunMinutes or -RunHours."
}

$supportedPlugins = @{
    "show-all-comments-in-one-page" = @{ Category = "XSS"; Service = $fuzzerService; ZipFiles = @("show-all-comments-in-one-page.zip") }
    "ubigeo-peru" = @{ Category = "SQLi"; Service = $fuzzerService; ZipFiles = @("ubigeo-peru.zip") }
    "photo-gallery" = @{ Category = "SQLi"; Service = $fuzzerService; ZipFiles = @("photo-gallery.zip") }
    "udraw" = @{ Category = "PathTraversal"; Service = $fuzzerService; ZipFiles = @("udraw.zip", "woocommerce.zip") }
    "crm-perks-forms" = @{ Category = "XSS"; Service = $fuzzerService; ZipFiles = @("crm-perks-forms.zip") }
    "joomsport-sports-league-results-management" = @{ Category = "Deserialization"; Service = $fuzzerService; ZipFiles = @("joomsport-sports-league-results-management.zip") }
    "phastpress" = @{ Category = "OpenRedirect"; Service = $fuzzerService; ZipFiles = @("phastpress.zip") }
    "seo-local-rank" = @{ Category = "PathTraversal"; Service = $fuzzerService; ZipFiles = @("seo-local-rank.zip") }
    "totop-link" = @{ Category = "Deserialization"; Service = $fuzzerService; ZipFiles = @("totop-link.zip") }
    "webp-converter-for-media" = @{ Category = "OpenRedirect"; Service = $fuzzerService; ZipFiles = @("webp-converter-for-media.zip") }
}

$supportedModes = @{
    "PHUZZ_RAW" = @{ Label = "PHUZZ_RAW"; ScoringMode = 1; EnableUopz = 0; HookFast = $false }
    "PHUZZ_TRACE" = @{ Label = "PHUZZ_TRACE"; ScoringMode = 1; EnableUopz = 1; HookFast = $false }
    "HOOK_TRACE" = @{ Label = "HOOK_TRACE"; ScoringMode = 2; EnableUopz = 1; HookFast = $false }
    "HOOK_FAST" = @{ Label = "HOOK_FAST"; ScoringMode = 1; EnableUopz = 0; HookFast = $true }
}

function Normalize-Selection {
    param(
        [string[]]$Values,
        [hashtable]$Supported,
        [string]$Kind
    )

    $selected = @()
    foreach ($value in $Values) {
        foreach ($part in ([string]$value).Split(",")) {
            $normalized = $part.Trim()
            if (-not $normalized) {
                continue
            }
            if (-not $Supported.ContainsKey($normalized)) {
                throw "Supported ${Kind}: $($Supported.Keys -join ', '). Received unsupported ${Kind}: $normalized"
            }
            if ($selected -notcontains $normalized) {
                $selected += $normalized
            }
        }
    }
    if ($selected.Count -eq 0) {
        throw "No ${Kind} selected."
    }
    return $selected
}

$selectedPlugins = Normalize-Selection -Values $Plugins -Supported $supportedPlugins -Kind "plugin"
$selectedModes = Normalize-Selection -Values $Modes -Supported $supportedModes -Kind "mode"
$benchmarkTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$benchmarkBaseRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot
} else {
    Join-Path $scriptRoot $OutputRoot
}
$completedBenchmarkRoots = @()

function Assert-PathExists {
    param(
        [string]$Path,
        [string]$Hint
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing required file: $Path`n$Hint"
    }
}

function Assert-PluginZipAssets {
    param(
        [string]$PluginSlug,
        [hashtable]$PluginConfig
    )

    foreach ($zipFile in @($PluginConfig.ZipFiles)) {
        $zipPath = Join-Path $pluginZipRoot $zipFile
        if (-not (Test-Path -LiteralPath $zipPath)) {
            throw "Missing plugin ZIP '$zipFile' for '$PluginSlug'. Download it into $pluginZipRoot before benchmarking."
        }
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
        }
        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for $Url to return HTTP 200 within $TimeoutSeconds seconds."
}

function Clear-LocalFuzzerOutput {
    if (-not (Test-Path -LiteralPath $localFuzzerOutputDir)) {
        return
    }

    $resolved = (Resolve-Path -LiteralPath $localFuzzerOutputDir).Path
    if (-not $resolved.StartsWith((Join-Path $scriptRoot "fuzzer\output"), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clear unexpected path: $resolved"
    }

    Remove-Item -Recurse -Force -LiteralPath $resolved
}

function Reset-ComposeState {
    param([string[]]$ComposeArgs)

    Write-Host "Resetting Docker Compose state"
    Invoke-Compose -ComposeArgs $ComposeArgs -AdditionalArgs @("down", "--volumes", "--remove-orphans")
}

function Get-ComposeContainerId {
    param(
        [string[]]$ComposeArgs,
        [string]$ServiceName
    )

    return (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q $ServiceName).Trim()
}

function Assert-ServiceRunning {
    param(
        [string[]]$ComposeArgs,
        [string]$ServiceName
    )

    $containerId = Get-ComposeContainerId -ComposeArgs $ComposeArgs -ServiceName $ServiceName
    if (-not $containerId) {
        throw "Could not resolve container id for service '$ServiceName'."
    }

    $status = (docker inspect -f "{{.State.Status}}" $containerId).Trim()
    if ($status -ne "running") {
        throw "Service '$ServiceName' is not running. Current status: $status"
    }
}

function Wait-ForFirstRunActivity {
    param(
        [string]$WebContainerId,
        [bool]$NeedsHookArtifact,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($NeedsHookArtifact) {
            $artifact = (docker exec $WebContainerId sh -lc "find /shared-tmpfs/hook-coverage/requests -maxdepth 1 -name '*.json' -print -quit" 2>$null).Trim()
            if ($LASTEXITCODE -eq 0 -and $artifact) {
                Write-Host "First hook request artifact observed: $artifact"
                return
            }
        } else {
            $eventPath = Join-Path $localFuzzerOutputDir "request-events.jsonl"
            if (Test-Path -LiteralPath $eventPath) {
                $length = (Get-Item -LiteralPath $eventPath).Length
                if ($length -gt 0) {
                    Write-Host "First fuzzer request event observed: $eventPath"
                    return
                }
            }
        }
        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for first run activity within $TimeoutSeconds seconds."
}

function Copy-RunArtifacts {
    param(
        [string[]]$ComposeArgs,
        [string]$RunDir,
        [string]$WebContainerId,
        [string]$FuzzerServiceName
    )

    $requestsDir = Join-Path $RunDir "requests"
    $fuzzerOutputCopy = Join-Path $RunDir "fuzzer-output"
    New-Item -ItemType Directory -Force -Path $requestsDir | Out-Null
    New-Item -ItemType Directory -Force -Path $fuzzerOutputCopy | Out-Null

    if (Test-Path -LiteralPath $localFuzzerOutputDir) {
        Copy-Item -Recurse -Force -Path (Join-Path $localFuzzerOutputDir "*") -Destination $fuzzerOutputCopy -ErrorAction SilentlyContinue
    }

    docker exec $WebContainerId sh -lc "test -d /shared-tmpfs/hook-coverage/requests" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        docker cp "${WebContainerId}:/shared-tmpfs/hook-coverage/requests/." $requestsDir | Out-Null
    }

    docker exec $WebContainerId sh -lc "test -f /shared-tmpfs/hook-coverage/total_coverage.json" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        docker cp "${WebContainerId}:/shared-tmpfs/hook-coverage/total_coverage.json" (Join-Path $RunDir "total_coverage.json") | Out-Null
    }

    $fuzzerLogPath = Join-Path $RunDir "fuzzer.log"
    $lines = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] logs $FuzzerServiceName --tail=400
    if ($LASTEXITCODE -eq 0) {
        Set-Content -Path $fuzzerLogPath -Value $lines -Encoding UTF8
    }
}

function Get-ActivePlugins {
    param([string[]]$ComposeArgs)

    $output = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T web sh -lc "cd /var/www/html && ./wp-cli.phar plugin list --allow-root --status=active --field=name"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read active plugins."
    }
    return @(
        $output | Where-Object {
            (-not [string]::IsNullOrWhiteSpace($_)) -and
            ($_ -notmatch "Deprecated:") -and
            ($_ -notmatch "Cannot load Zend OPcache")
        }
    )
}

function Get-ContainerEnvValue {
    param(
        [string[]]$ComposeArgs,
        [string]$ServiceName,
        [string]$VariableName,
        [switch]$Optional
    )

    $value = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T $ServiceName printenv $VariableName
    if ($LASTEXITCODE -ne 0) {
        if ($Optional) {
            return ""
        }
        throw "Failed to read environment variable '$VariableName' from service '$ServiceName'."
    }
    return ($value | Select-Object -First 1).Trim()
}

function Assert-PluginRuntimeState {
    param(
        [string[]]$ComposeArgs,
        [string]$PluginSlug,
        [string]$FuzzerServiceName,
        [string]$ExpectedConfigFile = ""
    )

    $activePlugins = Get-ActivePlugins -ComposeArgs $ComposeArgs
    if ($activePlugins -notcontains $PluginSlug) {
        throw "Plugin '$PluginSlug' is not active after WordPress bootstrap."
    }

    $fuzzerConfig = Get-ContainerEnvValue -ComposeArgs $ComposeArgs -ServiceName $FuzzerServiceName -VariableName "FUZZER_CONFIG"
    $expectedFuzzerConfig = "wordpress/$PluginSlug"
    if ($fuzzerConfig -ne $expectedFuzzerConfig) {
        throw "Expected FUZZER_CONFIG=$expectedFuzzerConfig but got '$fuzzerConfig'."
    }

    if ($ExpectedConfigFile) {
        $fuzzerConfigFile = Get-ContainerEnvValue -ComposeArgs $ComposeArgs -ServiceName $FuzzerServiceName -VariableName "FUZZER_CONFIG_FILE"
        if ($fuzzerConfigFile -ne $ExpectedConfigFile) {
            throw "Expected FUZZER_CONFIG_FILE=$ExpectedConfigFile but got '$fuzzerConfigFile'."
        }
    }

    $webTargetPlugin = Get-ContainerEnvValue -ComposeArgs $ComposeArgs -ServiceName "web" -VariableName "WP_TARGET_PLUGIN"
    if ($webTargetPlugin -ne $PluginSlug) {
        throw "Expected WP_TARGET_PLUGIN=$PluginSlug but got '$webTargetPlugin'."
    }

    $coveragePath = Get-ContainerEnvValue -ComposeArgs $ComposeArgs -ServiceName "web" -VariableName "FUZZER_COVERAGE_PATH"
    $expectedCoverageSuffix = "/wp-content/plugins/$PluginSlug/"
    if (-not $coveragePath.EndsWith($expectedCoverageSuffix, [System.StringComparison]::Ordinal)) {
        throw "Expected FUZZER_COVERAGE_PATH to end with '$expectedCoverageSuffix' but got '$coveragePath'."
    }
}

function New-OverrideFile {
    param(
        [string]$PluginSlug,
        [string]$FuzzerServiceName,
        [hashtable]$ModeConfig,
        [string]$FuzzerConfigFile = ""
    )

    $path = Join-Path $env:TEMP ("phuzz-benchmark-{0}-{1}.override.yml" -f $PluginSlug, $ModeConfig.Label)
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/"
        "      WP_TARGET_PLUGIN: $PluginSlug"
        "      FUZZER_ENABLE_UOPZ: $($ModeConfig.EnableUopz)"
        "      FUZZER_HOOK_OUTPUT_DIR: /shared-tmpfs/hook-coverage"
        "  ${FuzzerServiceName}:"
        "    environment:"
        "      FUZZER_CONFIG: wordpress/$PluginSlug"
        "      PHUZZ_SCORING_MODE: $($ModeConfig.ScoringMode)"
        "      PHUZZ_WRITE_REQUEST_EVENTS: 1"
    )
    if ($FuzzerConfigFile) {
        $content += "      FUZZER_CONFIG_FILE: $FuzzerConfigFile"
    }
    Set-Content -LiteralPath $path -Value $content -Encoding ASCII
    return $path
}

function Invoke-RunSummary {
    param(
        [string]$RunDir,
        [string]$PluginSlug,
        [string]$ModeLabel,
        [int]$ModeValue,
        [int]$RunIndex,
        [int]$TimeBudgetSeconds
    )

    $outputPath = Join-Path $RunDir "benchmark_summary.json"
    python $summaryCliPath summarize-run `
        --run-dir $RunDir `
        --plugin $PluginSlug `
        --mode-label $ModeLabel `
        --mode-value $ModeValue `
        --run-id $RunIndex `
        --time-budget-seconds $TimeBudgetSeconds `
        --bucket-minutes $BucketMinutes `
        --output $outputPath
    if ($LASTEXITCODE -ne 0) {
        throw "Run summary failed for $RunDir"
    }
}

function Invoke-BatchSummary {
    param([string]$BenchmarkRoot)

    python $summaryCliPath summarize-batch `
        --benchmark-root $BenchmarkRoot `
        --output-root $BenchmarkRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Batch summary failed for $BenchmarkRoot"
    }
}

function Write-RunManifest {
    param(
        [string]$RunDir,
        [hashtable]$Manifest
    )

    $manifestPath = Join-Path $RunDir "run_manifest.json"
    $Manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}

function Convert-ToFuzzerContainerPath {
    param([string]$HostPath)

    $fuzzerRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot "fuzzer")).Path
    $resolved = (Resolve-Path -LiteralPath $HostPath).Path
    if (-not $resolved.StartsWith($fuzzerRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "FUZZER_CONFIG_FILE must be under '$fuzzerRoot' so the fuzzer container can read it. Got: $resolved"
    }
    $relative = $resolved.Substring($fuzzerRoot.Length).TrimStart("\", "/")
    return "/app/" + ($relative -replace "\\", "/")
}

function Invoke-RunPhase {
    param(
        [string]$PluginSlug,
        [hashtable]$PluginConfig,
        [hashtable]$ModeConfig,
        [string]$RunDir,
        [int]$RunIndex,
        [int]$DurationMinutes,
        [string]$FuzzerConfigFile = "",
        [switch]$SkipSummary,
        [switch]$SkipManifest
    )

    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
    $overridePath = New-OverrideFile -PluginSlug $PluginSlug -FuzzerServiceName $PluginConfig.Service -ModeConfig $ModeConfig -FuzzerConfigFile $FuzzerConfigFile
    $composeArgs = Get-ComposeArgs -OverridePath $overridePath

    try {
        Reset-ComposeState -ComposeArgs $composeArgs
        Clear-LocalFuzzerOutput

        Write-Host "Starting db and web for $PluginSlug ($($ModeConfig.Label))"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build")
        Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

        Write-Host "Starting fuzzer service $($PluginConfig.Service)"
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $PluginConfig.Service, "--build")
        Assert-ServiceRunning -ComposeArgs $composeArgs -ServiceName $PluginConfig.Service
        Assert-PluginRuntimeState -ComposeArgs $composeArgs -PluginSlug $PluginSlug -FuzzerServiceName $PluginConfig.Service -ExpectedConfigFile $FuzzerConfigFile

        $webContainerId = Get-ComposeContainerId -ComposeArgs $composeArgs -ServiceName "web"
        if (-not $webContainerId) {
            throw "Could not resolve web container id."
        }

        Wait-ForFirstRunActivity -WebContainerId $webContainerId -NeedsHookArtifact ([int]$ModeConfig.EnableUopz -eq 1) -TimeoutSeconds $FirstRequestTimeoutSeconds

        $deadline = (Get-Date).AddMinutes($DurationMinutes)
        while ((Get-Date) -lt $deadline) {
            Assert-ServiceRunning -ComposeArgs $composeArgs -ServiceName $PluginConfig.Service
            Start-Sleep -Seconds 15
        }

        Copy-RunArtifacts -ComposeArgs $composeArgs -RunDir $RunDir -WebContainerId $webContainerId -FuzzerServiceName $PluginConfig.Service

        if (-not $SkipSummary) {
            Invoke-RunSummary -RunDir $RunDir -PluginSlug $PluginSlug -ModeLabel $ModeConfig.Label -ModeValue $ModeConfig.ScoringMode -RunIndex $RunIndex -TimeBudgetSeconds ($DurationMinutes * 60)
        }

        if (-not $SkipManifest) {
            Write-RunManifest -RunDir $RunDir -Manifest @{
                plugin = $PluginSlug
                mode = $ModeConfig.Label
                scoring_mode = $ModeConfig.ScoringMode
                fuzzer_enable_uopz = $ModeConfig.EnableUopz
                run_minutes = $DurationMinutes
                bucket_minutes = $BucketMinutes
                fuzzer_config = "wordpress/$PluginSlug"
                fuzzer_config_file = $FuzzerConfigFile
            }
        }
    } finally {
        if (Test-Path -LiteralPath $overridePath) {
            Remove-Item -Force -LiteralPath $overridePath
        }
    }
}

function Invoke-HookFastRun {
    param(
        [string]$PluginSlug,
        [hashtable]$PluginConfig,
        [string]$RunDir,
        [int]$RunIndex
    )

    $traceDuration = [Math]::Min($TraceMinutes, [Math]::Max(1, $totalRunMinutes - 1))
    $fastDuration = [Math]::Max(1, $totalRunMinutes - $traceDuration)
    $traceDir = Join-Path $RunDir "trace-phase"
    $seedExportDir = Join-Path $RunDir "seed-export"
    $fastConfigPath = Join-Path $RunDir "hook-fast-config.json"
    $sourceConfigPath = Join-Path $scriptRoot "fuzzer\configs\wordpress\$PluginSlug.json"

    Invoke-RunPhase `
        -PluginSlug $PluginSlug `
        -PluginConfig $PluginConfig `
        -ModeConfig $supportedModes["HOOK_TRACE"] `
        -RunDir $traceDir `
        -RunIndex $RunIndex `
        -DurationMinutes $traceDuration `
        -SkipSummary `
        -SkipManifest

    $coveragePath = Join-Path $traceDir "total_coverage.json"
    if (-not (Test-Path -LiteralPath $coveragePath)) {
        throw "HOOK_FAST trace phase did not produce total_coverage.json at $coveragePath"
    }

    New-Item -ItemType Directory -Force -Path $seedExportDir | Out-Null
    python $seedExportCliPath `
        --coverage-file $coveragePath `
        --output-dir $seedExportDir `
        --source-config $sourceConfigPath `
        --fast-config-output $fastConfigPath `
        --target-base "http://web" `
        --seed-limit $FastSeedLimit
    if ($LASTEXITCODE -ne 0) {
        throw "HOOK_FAST seed export failed."
    }
    Assert-PathExists -Path (Join-Path $seedExportDir "hook_gap_report.json") -Hint "HOOK_FAST seed export must write hook_gap_report.json."

    $containerConfigPath = Convert-ToFuzzerContainerPath -HostPath $fastConfigPath
    Invoke-RunPhase `
        -PluginSlug $PluginSlug `
        -PluginConfig $PluginConfig `
        -ModeConfig $supportedModes["HOOK_FAST"] `
        -RunDir $RunDir `
        -RunIndex $RunIndex `
        -DurationMinutes $fastDuration `
        -FuzzerConfigFile $containerConfigPath `
        -SkipManifest

    Write-RunManifest -RunDir $RunDir -Manifest @{
        plugin = $PluginSlug
        mode = "HOOK_FAST"
        scoring_mode = $supportedModes["HOOK_FAST"].ScoringMode
        fuzzer_enable_uopz = $supportedModes["HOOK_FAST"].EnableUopz
        run_minutes = $totalRunMinutes
        trace_minutes = $traceDuration
        fast_minutes = $fastDuration
        bucket_minutes = $BucketMinutes
        fast_seed_limit = $FastSeedLimit
        trace_phase_dir = $traceDir
        seed_export_dir = $seedExportDir
        fast_config_host_path = $fastConfigPath
        fast_config_container_path = $containerConfigPath
        fuzzer_config = "wordpress/$PluginSlug"
        fuzzer_config_file = $containerConfigPath
    }
}

Assert-PathExists -Path $summaryCliPath -Hint "Benchmarking needs the Python summarizer."
Assert-PathExists -Path $seedExportCliPath -Hint "HOOK_FAST needs the seed export CLI."
New-Item -ItemType Directory -Force -Path $benchmarkBaseRoot | Out-Null

try {
    Write-Host "Checking Docker and Python availability"
    docker compose version | Out-Null
    python --version | Out-Null

    foreach ($pluginSlug in $selectedPlugins) {
        $pluginConfig = $supportedPlugins[$pluginSlug]
        Assert-PluginZipAssets -PluginSlug $pluginSlug -PluginConfig $pluginConfig
        $pluginBenchmarkRoot = Join-Path $benchmarkBaseRoot "$benchmarkTimestamp-$pluginSlug"
        New-Item -ItemType Directory -Force -Path $pluginBenchmarkRoot | Out-Null

        foreach ($modeName in $selectedModes) {
            $modeConfig = $supportedModes[$modeName]
            for ($runIndex = 1; $runIndex -le $RunsPerMode; $runIndex++) {
                $runName = "{0}-run-{1:d2}" -f $modeConfig.Label, $runIndex
                $runDir = Join-Path $pluginBenchmarkRoot $runName
                Write-Host "=== Starting $runName ($pluginSlug, ${totalRunMinutes}m) ==="

                if ($modeConfig.HookFast) {
                    Invoke-HookFastRun -PluginSlug $pluginSlug -PluginConfig $pluginConfig -RunDir $runDir -RunIndex $runIndex
                } else {
                    Invoke-RunPhase `
                        -PluginSlug $pluginSlug `
                        -PluginConfig $pluginConfig `
                        -ModeConfig $modeConfig `
                        -RunDir $runDir `
                        -RunIndex $runIndex `
                        -DurationMinutes $totalRunMinutes
                }
            }
        }

        Invoke-BatchSummary -BenchmarkRoot $pluginBenchmarkRoot
        $completedBenchmarkRoots += $pluginBenchmarkRoot
        Write-Host "Benchmark artifacts written to: $pluginBenchmarkRoot"
    }
} finally {
    if ($TearDownAfterBenchmark) {
        Reset-ComposeState -ComposeArgs $composeBaseArgs
    }
}

if ($completedBenchmarkRoots.Count -gt 0) {
    Write-Host "Completed benchmark roots:"
    foreach ($path in $completedBenchmarkRoots) {
        Write-Host " - $path"
    }
}
