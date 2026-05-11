param(
    [int]$RunsPerMode = 5,
    [int]$RunMinutes = 30,
    [string]$Plugin = "show-all-comments-in-one-page",
    [string]$OutputRoot = "fuzzer\output\benchmarks",
    [int]$WebTimeoutSeconds = 240,
    [int]$FirstRequestTimeoutSeconds = 180,
    [switch]$TearDownAfterBenchmark
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$scoringEnvPath = Join-Path $scriptRoot "fuzzer\scoring.env"
$localFuzzerOutputDir = Join-Path $scriptRoot "fuzzer\output\fuzzer-1"
$summaryCliPath = Join-Path $scriptRoot "fuzzer\benchmarking\summary.py"
$webUrl = "http://localhost:8080/"
$supportedPlugins = @{
    "show-all-comments-in-one-page" = "fuzzer-wordpress-show-all-comments-in-one-page-1"
}

if (-not $supportedPlugins.ContainsKey($Plugin)) {
    throw "This first benchmark pass only supports plugin '$($supportedPlugins.Keys -join "', '")'. Received: $Plugin"
}

$fuzzerService = $supportedPlugins[$Plugin]
$benchmarkTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$benchmarkRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot
} else {
    Join-Path $scriptRoot $OutputRoot
}
$benchmarkRoot = Join-Path $benchmarkRoot "$benchmarkTimestamp-$Plugin"
$originalScoringEnv = Get-Content -Path $scoringEnvPath -Raw

function Assert-PathExists {
    param(
        [string]$Path,
        [string]$Hint
    )

    if (-not (Test-Path -LiteralPath $Path)) {
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
    Write-Host "Resetting Docker Compose state"
    docker compose down --volumes --remove-orphans
}

function Get-ComposeContainerId {
    param(
        [string]$ServiceName
    )

    return (docker compose ps -q $ServiceName).Trim()
}

function Assert-ServiceRunning {
    param(
        [string]$ServiceName
    )

    $containerId = Get-ComposeContainerId -ServiceName $ServiceName
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
        [string]$RunDir,
        [string]$WebContainerId
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
}

function Invoke-RunSummary {
    param(
        [string]$RunDir,
        [string]$ModeLabel,
        [int]$ModeValue,
        [int]$RunIndex,
        [int]$TimeBudgetSeconds
    )

    $outputPath = Join-Path $RunDir "benchmark_summary.json"
    python $summaryCliPath summarize-run `
        --run-dir $RunDir `
        --plugin $Plugin `
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
New-Item -ItemType Directory -Force -Path $benchmarkRoot | Out-Null

$modes = @(
    @{ Label = "PHUZZ"; Value = 1 },
    @{ Label = "HOOK"; Value = 2 }
)

try {
    Write-Host "Checking Docker and Python availability"
    docker compose version | Out-Null
    python --version | Out-Null

    foreach ($mode in $modes) {
        for ($runIndex = 1; $runIndex -le $RunsPerMode; $runIndex++) {
            $modeLabel = [string]$mode.Label
            $modeValue = [int]$mode.Value
            $runName = "{0}-run-{1:d2}" -f $modeLabel, $runIndex
            $runDir = Join-Path $benchmarkRoot $runName
            New-Item -ItemType Directory -Force -Path $runDir | Out-Null

            Write-Host "=== Starting $runName ($Plugin, mode=$modeValue, ${RunMinutes}m) ==="
            Set-ScoringMode -Mode $modeValue
            Reset-ComposeState
            Clear-LocalFuzzerOutput

            Write-Host "Starting db and web"
            docker compose up -d db web --build
            Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds

            Write-Host "Starting fuzzer service $fuzzerService"
            docker compose up -d $fuzzerService --build
            Assert-ServiceRunning -ServiceName $fuzzerService

            $webContainerId = Get-ComposeContainerId -ServiceName "web"
            if (-not $webContainerId) {
                throw "Could not resolve web container id."
            }

            Wait-ForFirstRequestArtifact -WebContainerId $webContainerId -TimeoutSeconds $FirstRequestTimeoutSeconds

            $benchmarkDeadline = (Get-Date).AddMinutes($RunMinutes)
            while ((Get-Date) -lt $benchmarkDeadline) {
                Assert-ServiceRunning -ServiceName $fuzzerService
                Start-Sleep -Seconds 15
            }

            Copy-RunArtifacts -RunDir $runDir -WebContainerId $webContainerId
            Invoke-RunSummary -RunDir $runDir -ModeLabel $modeLabel -ModeValue $modeValue -RunIndex $runIndex -TimeBudgetSeconds ($RunMinutes * 60)
        }
    }

    Invoke-BatchSummary -BenchmarkRoot $benchmarkRoot
    Write-Host "Benchmark artifacts written to: $benchmarkRoot"
} finally {
    Set-Content -Path $scoringEnvPath -Value $originalScoringEnv -Encoding UTF8
    if ($TearDownAfterBenchmark) {
        Reset-ComposeState
    }
}
