param(
    [int]$RunsPerMode = 5,
    [int]$RunMinutes = 30,
    [Alias("Plugin")]
    [string[]]$Plugins = @(
        "photo-gallery",
        "crm-perks-forms",
        "seo-local-rank",
        "totop-link",
        "webp-converter-for-media"
    ),
    [string]$OutputRoot = "fuzzer\output\benchmarks",
    [int]$WebTimeoutSeconds = 240,
    [int]$FirstRequestTimeoutSeconds = 180,
    [switch]$TearDownAfterBenchmark
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$scoringEnvPath = Join-Path $scriptRoot "fuzzer\scoring.env"
$localFuzzerOutputDir = Join-Path $scriptRoot "fuzzer\output\fuzzer-1"
$summaryCliPath = Join-Path $scriptRoot "fuzzer\benchmarking\summary.py"
$pluginZipRoot = Join-Path $scriptRoot "web\applications\wordpress\_plugins"
$webUrl = "http://localhost:8080/"
$fuzzerService = "fuzzer-wordpress-plugin"
$composeBaseArgs = @("docker", "compose", "-f", "docker-compose.yml")
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
$selectedPlugins = @()
foreach ($pluginName in $Plugins) {
    $normalizedPlugin = [string]$pluginName
    $normalizedPlugin = $normalizedPlugin.Trim()
    if (-not $normalizedPlugin) {
        continue
    }
    if (-not $supportedPlugins.ContainsKey($normalizedPlugin)) {
        throw "Supported benchmark plugins: $($supportedPlugins.Keys -join ', '). Received unsupported plugin: $normalizedPlugin"
    }
    if ($selectedPlugins -notcontains $normalizedPlugin) {
        $selectedPlugins += $normalizedPlugin
    }
}
if ($selectedPlugins.Count -eq 0) {
    throw "No plugins selected for benchmarking."
}

$benchmarkTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$benchmarkBaseRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot
} else {
    Join-Path $scriptRoot $OutputRoot
}
$originalScoringEnv = Get-Content -Path $scoringEnvPath -Raw
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

function Set-ScoringMode {
    param(
        [int]$Mode
    )

    $content = Get-Content -Path $scoringEnvPath -Raw
    $updated = [regex]::Replace(
        $content,
        "(?m)^PHUZZ_SCORING_MODE=.*$",
        "PHUZZ_SCORING_MODE=$Mode"
    )
    if ($updated -eq $content) {
        throw "Could not find PHUZZ_SCORING_MODE in $scoringEnvPath"
    }
    Set-Content -Path $scoringEnvPath -Value $updated -Encoding UTF8
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
    param(
        [string[]]$ComposeArgs
    )

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

function Wait-ForFirstRequestArtifact {
    param(
        [string]$WebContainerId,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $artifact = (docker exec $WebContainerId sh -lc "find /shared-tmpfs/hook-coverage/requests -maxdepth 1 -name '*.json' -print -quit" 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $artifact) {
            Write-Host "First request artifact observed: $artifact"
            return
        }
        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for the first hook request artifact within $TimeoutSeconds seconds."
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

    docker cp "${WebContainerId}:/shared-tmpfs/hook-coverage/requests/." $requestsDir | Out-Null

    $hasCoverageSnapshot = (docker exec $WebContainerId sh -lc "test -f /shared-tmpfs/hook-coverage/total_coverage.json" 2>$null)
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
        [string]$VariableName
    )

    $value = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] exec -T $ServiceName printenv $VariableName
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read environment variable '$VariableName' from service '$ServiceName'."
    }
    return ($value | Select-Object -First 1).Trim()
}

function Assert-PluginRuntimeState {
    param(
        [string[]]$ComposeArgs,
        [string]$PluginSlug,
        [string]$FuzzerServiceName
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
        [string]$FuzzerServiceName
    )

    $path = Join-Path $env:TEMP ("phuzz-benchmark-{0}.override.yml" -f $PluginSlug)
    $content = @(
        "services:"
        "  web:"
        "    environment:"
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/"
        "      WP_TARGET_PLUGIN: $PluginSlug"
        "  ${FuzzerServiceName}:"
        "    environment:"
        "      FUZZER_CONFIG: wordpress/$PluginSlug"
    )
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
        --output $outputPath
}

function Invoke-BatchSummary {
    param(
        [string]$BenchmarkRoot
    )

    python $summaryCliPath summarize-batch `
        --benchmark-root $BenchmarkRoot `
        --output-root $BenchmarkRoot
}

Assert-PathExists -Path $scoringEnvPath -Hint "Benchmarking needs the shared scoring env file."
Assert-PathExists -Path $summaryCliPath -Hint "Benchmarking needs the Python summarizer."
New-Item -ItemType Directory -Force -Path $benchmarkBaseRoot | Out-Null

$modes = @(
    @{ Label = "PHUZZ"; Value = 1 },
    @{ Label = "HOOK"; Value = 2 }
)

try {
    Write-Host "Checking Docker and Python availability"
    docker compose version | Out-Null
    python --version | Out-Null

    foreach ($pluginSlug in $selectedPlugins) {
        $pluginConfig = $supportedPlugins[$pluginSlug]
        Assert-PluginZipAssets -PluginSlug $pluginSlug -PluginConfig $pluginConfig
        $pluginBenchmarkRoot = Join-Path $benchmarkBaseRoot "$benchmarkTimestamp-$pluginSlug"
        $overridePath = New-OverrideFile -PluginSlug $pluginSlug -FuzzerServiceName $pluginConfig.Service
        $composeArgs = Get-ComposeArgs -OverridePath $overridePath
        New-Item -ItemType Directory -Force -Path $pluginBenchmarkRoot | Out-Null

        try {
            foreach ($mode in $modes) {
                for ($runIndex = 1; $runIndex -le $RunsPerMode; $runIndex++) {
                    $modeLabel = [string]$mode.Label
                    $modeValue = [int]$mode.Value
                    $runName = "{0}-run-{1:d2}" -f $modeLabel, $runIndex
                    $runDir = Join-Path $pluginBenchmarkRoot $runName
                    New-Item -ItemType Directory -Force -Path $runDir | Out-Null

                    Write-Host "=== Starting $runName ($pluginSlug, mode=$modeValue, ${RunMinutes}m) ==="
                    Set-ScoringMode -Mode $modeValue
                    Reset-ComposeState -ComposeArgs $composeArgs
                    Clear-LocalFuzzerOutput

                    Write-Host "Starting db and web for $pluginSlug"
                    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build")
                    Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

                    Write-Host "Starting fuzzer service $($pluginConfig.Service)"
                    Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", $pluginConfig.Service, "--build")
                    Assert-ServiceRunning -ComposeArgs $composeArgs -ServiceName $pluginConfig.Service
                    Assert-PluginRuntimeState -ComposeArgs $composeArgs -PluginSlug $pluginSlug -FuzzerServiceName $pluginConfig.Service

                    $webContainerId = Get-ComposeContainerId -ComposeArgs $composeArgs -ServiceName "web"
                    if (-not $webContainerId) {
                        throw "Could not resolve web container id."
                    }

                    Wait-ForFirstRequestArtifact -WebContainerId $webContainerId -TimeoutSeconds $FirstRequestTimeoutSeconds

                    $benchmarkDeadline = (Get-Date).AddMinutes($RunMinutes)
                    while ((Get-Date) -lt $benchmarkDeadline) {
                        Assert-ServiceRunning -ComposeArgs $composeArgs -ServiceName $pluginConfig.Service
                        Start-Sleep -Seconds 15
                    }

                    Copy-RunArtifacts -ComposeArgs $composeArgs -RunDir $runDir -WebContainerId $webContainerId -FuzzerServiceName $pluginConfig.Service
                    Invoke-RunSummary -RunDir $runDir -PluginSlug $pluginSlug -ModeLabel $modeLabel -ModeValue $modeValue -RunIndex $runIndex -TimeBudgetSeconds ($RunMinutes * 60)
                }
            }

            Invoke-BatchSummary -BenchmarkRoot $pluginBenchmarkRoot
            $completedBenchmarkRoots += $pluginBenchmarkRoot
            Write-Host "Benchmark artifacts written to: $pluginBenchmarkRoot"
        } finally {
            if (Test-Path -LiteralPath $overridePath) {
                Remove-Item -Force -LiteralPath $overridePath
            }
        }
    }
} finally {
    Set-Content -Path $scoringEnvPath -Value $originalScoringEnv -Encoding UTF8
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
