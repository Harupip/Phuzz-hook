param(
    [ValidateSet("default", "seed-config", "generated", "recursive")]
    [string]$Mode,
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug,
    [string[]]$RecursiveInputFile,
    [string]$RecursiveHookCoverageDir,
    [string]$RecursiveBaseUrl = "http://localhost:8080",
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [ValidateRange(1, 86400)]
    [int]$GeneratedConfigTimeoutSeconds = 300,
    [ValidateRange(1, 20)]
    [int]$MaxHookDepth = 3,
    [ValidateRange(1, 300)]
    [int]$RecursiveValidationTimeoutSeconds = 10,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$runnerPath = Join-Path $scriptRoot "scripts\wordpress\run-wordpress-phuzz.ps1"
$recursiveHelperPath = Join-Path $scriptRoot "fuzzer\hook_energy\recursive_child_hook_seeds.py"
$pluginDir = Join-Path $scriptRoot "web\applications\wordpress\_plugins"
$configDir = Join-Path $scriptRoot "fuzzer\configs\wordpress"

function Show-Usage {
    Write-Host @"
Guided PHUZZ runner

Usage:
  .\phuzz.ps1
  .\phuzz.ps1 -Mode default
  .\phuzz.ps1 -Mode seed-config -NoFollowLogs
  .\phuzz.ps1 -Mode generated -PluginSlug gamipress -GeneratedConfigTimeoutSeconds 300 -NoFollowLogs
  .\phuzz.ps1 -Mode recursive
  .\phuzz.ps1 -Mode recursive -RecursiveInputFile fuzzer\output\hook-coverage\requests\latest.json
  .\phuzz.ps1 -Mode generated -GeneratedConfigTimeoutSeconds 300 -NoFollowLogs -DryRun

Modes:
  default      Start WordPress PHUZZ with existing behavior.
  seed-config  Start WordPress, export hook seeds, generate PHUZZ configs, do not follow logs.
  generated    Export seeds/configs, then run generated hook configs sequentially.
  recursive    Generate recursive child-hook seeds/configs from request artifacts.

Useful options:
  -PluginSlug <slug>               WordPress plugin ZIP/config slug. Default: show-all-comments-in-one-page.
  -ForcePlugins                    Re-download the default plugin ZIP when using the default target.
  -NoFollowLogs                    Return after startup instead of following fuzzer logs.
  -WebTimeoutSeconds <seconds>     Wait window for WordPress HTTP 200. Default: 240.
  -SeedWaitSeconds <seconds>       Wait window for live hook coverage snapshot. Default: 45.
  -GeneratedConfigTimeoutSeconds   Per generated-config run window. Default: 300.
  -RecursiveInputFile <path>       Child-hook input artifact. Repeat for multiple files.
  -RecursiveHookCoverageDir <path> Hook coverage dir with requests/ for recursive validation.
  -RecursiveBaseUrl <url>          WordPress base URL for recursive validation. Default: http://localhost:8080.
  -MaxHookDepth <depth>            Recursive child-hook depth. Default: 3.
  -RecursiveValidationTimeoutSeconds <seconds> Per child-hook replay timeout. Default: 10.
  -DryRun                          Print the delegated command without running it.
"@
}

function Get-LocalPluginSlugs {
    if (-not (Test-Path -LiteralPath $pluginDir)) {
        return @()
    }

    return @(
        Get-ChildItem -LiteralPath $pluginDir -Filter "*.zip" |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) } |
            Where-Object { Test-Path -LiteralPath (Join-Path $configDir "$_.json") } |
            Sort-Object -Unique
    )
}

function Read-MenuMode {
    Write-Host ""
    Write-Host "Choose PHUZZ workflow:"
    Write-Host "  1) default     - Start WordPress PHUZZ with existing behavior"
    Write-Host "  2) seed-config - Start web, export hook seeds, generate PHUZZ configs"
    Write-Host "  3) generated   - Generate configs, then run them sequentially"
    Write-Host "  4) recursive   - Generate recursive child-hook seeds/configs from request artifacts"

    $choice = (Read-Host "Select [1-4]").Trim()
    switch ($choice) {
        "1" { return "default" }
        "2" { return "seed-config" }
        "3" { return "generated" }
        "4" { return "recursive" }
        default { throw "Invalid selection '$choice'. Choose 1, 2, 3, or 4." }
    }
}

function Read-PluginSlug {
    $slugs = @(Get-LocalPluginSlugs)
    if ($slugs.Count -eq 0) {
        Write-Host "No local plugin ZIP with matching PHUZZ config found. Using default: show-all-comments-in-one-page"
        return "show-all-comments-in-one-page"
    }

    Write-Host ""
    Write-Host "Choose local WordPress plugin with matching PHUZZ config:"
    for ($index = 0; $index -lt $slugs.Count; $index++) {
        Write-Host ("  {0}) {1}" -f ($index + 1), $slugs[$index])
    }

    $choice = (Read-Host "Select [1-$($slugs.Count)] or press Enter for show-all-comments-in-one-page").Trim()
    if ([string]::IsNullOrWhiteSpace($choice)) {
        return "show-all-comments-in-one-page"
    }

    $selectedIndex = 0
    if (-not [int]::TryParse($choice, [ref]$selectedIndex)) {
        throw "Invalid plugin selection '$choice'. Choose a number."
    }
    if ($selectedIndex -lt 1 -or $selectedIndex -gt $slugs.Count) {
        throw "Invalid plugin selection '$choice'. Choose 1-$($slugs.Count)."
    }

    return $slugs[$selectedIndex - 1]
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default
    )

    $suffix = "[y/N]"
    if ($Default) {
        $suffix = "[Y/n]"
    }

    $answer = (Read-Host "$Prompt $suffix").Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Default
    }

    if ($answer -in @("y", "yes")) {
        return $true
    }

    if ($answer -in @("n", "no")) {
        return $false
    }

    throw "Invalid answer '$answer'. Use y or n."
}

function Format-Command {
    param(
        [string]$CommandPath,
        [hashtable]$Parameters
    )

    $parts = @("&", "`"$CommandPath`"")
    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
        if ($value -is [switch] -or $value -is [bool]) {
            if ($value) {
                $parts += "-$key"
            }
        } else {
            $parts += "-$key"
            $parts += "$value"
        }
    }
    return ($parts -join " ")
}

function Format-ArgumentCommand {
    param(
        [string]$Command,
        [string[]]$Arguments
    )

    $parts = @($Command)
    foreach ($argument in $Arguments) {
        if ($argument -match '\s') {
            $parts += "`"$argument`""
        } else {
            $parts += $argument
        }
    }
    return ($parts -join " ")
}

function Copy-ContainerRequestArtifacts {
    param([string]$OutputDir)

    $requestsDir = "/shared-tmpfs/hook-coverage/requests"
    $coverageDir = Join-Path $OutputDir ("coverage-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
    $requestsOutputDir = Join-Path $coverageDir "requests"
    New-Item -ItemType Directory -Force -Path $requestsOutputDir | Out-Null

    $artifactNames = docker compose exec -T web sh -lc "find $requestsDir -maxdepth 1 -type f -printf '%f\n'"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list request artifacts from web:$requestsDir. Run a mode that starts WordPress and creates hook coverage first."
    }

    $copied = @()
    foreach ($name in $artifactNames) {
        $trimmed = "$name".Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }
        if ([System.IO.Path]::GetFileName($trimmed) -ne $trimmed) {
            throw "Invalid request artifact name from container: $trimmed"
        }

        $target = Join-Path $requestsOutputDir $trimmed
        docker compose exec -T web cat "$requestsDir/$trimmed" | Set-Content -LiteralPath $target -Encoding UTF8
        if ($LASTEXITCODE -ne 0) {
            throw "Could not copy request artifact from web:$requestsDir/$trimmed"
        }
        $copied += $target
    }

    if ($copied.Count -eq 0) {
        throw "No request artifacts found in web:$requestsDir. Run mode generated first, or pass -RecursiveInputFile."
    }

    return [PSCustomObject]@{
        CoverageDir = $coverageDir
        InputFiles = $copied
    }
}

function Write-RecursiveContainerTarget {
    $targetPlugin = (docker compose exec -T web printenv WP_TARGET_PLUGIN 2>$null)
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($targetPlugin)) {
        Write-Host "Mode recursive target plugin: $($targetPlugin.Trim())"
    } else {
        Write-Host "Mode recursive target plugin: <not detected from web container>"
    }

    $coveragePath = (docker compose exec -T web printenv FUZZER_COVERAGE_PATH 2>$null)
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($coveragePath)) {
        Write-Host "Mode recursive coverage path: $($coveragePath.Trim())"
    }
}

function Start-ArtifactSyncJob {
    param([string]$CoverageDir)

    $requestsDir = "/shared-tmpfs/hook-coverage/requests"
    $workDir = $scriptRoot
    return Start-Job -ScriptBlock {
        param($WorkDir, $RequestsDir, $CoverageDir)

        Set-Location $WorkDir
        $targetDir = Join-Path $CoverageDir "requests"
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        while ($true) {
            $artifactNames = docker compose exec -T web sh -lc "find $RequestsDir -maxdepth 1 -type f -printf '%f\n'" 2>$null
            if ($LASTEXITCODE -eq 0) {
                foreach ($name in $artifactNames) {
                    $trimmed = "$name".Trim()
                    if ([string]::IsNullOrWhiteSpace($trimmed)) {
                        continue
                    }
                    if ([System.IO.Path]::GetFileName($trimmed) -ne $trimmed) {
                        continue
                    }
                    docker compose exec -T web cat "$RequestsDir/$trimmed" 2>$null |
                        Set-Content -LiteralPath (Join-Path $targetDir $trimmed) -Encoding UTF8
                }
            }
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList $workDir, $requestsDir, $CoverageDir
}

function Resolve-RecursiveHookCoverageDir {
    param([string[]]$InputFiles)

    if (-not [string]::IsNullOrWhiteSpace($RecursiveHookCoverageDir)) {
        return $RecursiveHookCoverageDir
    }

    $parents = @(
        $InputFiles |
            ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
            ForEach-Object { Split-Path -Parent $_ } |
            Sort-Object -Unique
    )
    if ($parents.Count -eq 1 -and (Split-Path -Leaf $parents[0]) -eq "requests") {
        return (Split-Path -Parent $parents[0])
    }

    throw "Pass -RecursiveHookCoverageDir when using -RecursiveInputFile outside a requests/ directory."
}

function Invoke-RecursiveChildHookMode {
    $outputDir = Join-Path $scriptRoot "fuzzer\output\recursive-child-hooks"
    $inputFiles = @($RecursiveInputFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $hookCoverageDir = $RecursiveHookCoverageDir
    $syncJob = $null

    Write-Host "Mode recursive step 1/4: preparing request artifacts"
    if ($inputFiles.Count -eq 0 -and -not $DryRun) {
        Write-RecursiveContainerTarget
        $copyResult = Copy-ContainerRequestArtifacts -OutputDir $outputDir
        $inputFiles = @($copyResult.InputFiles)
        $hookCoverageDir = $copyResult.CoverageDir
    }
    if ($inputFiles.Count -eq 0) {
        $inputFiles = @("<copied request artifacts from web:/shared-tmpfs/hook-coverage/requests>")
    }
    if ([string]::IsNullOrWhiteSpace($hookCoverageDir)) {
        if ($DryRun) {
            $hookCoverageDir = "<coverage dir inferred from request artifacts>"
        } else {
            $hookCoverageDir = Resolve-RecursiveHookCoverageDir -InputFiles $inputFiles
        }
    }

    $recursiveArgs = @(
        $recursiveHelperPath,
        "--output-dir", $outputDir,
        "--max-hook-depth", "$MaxHookDepth",
        "--base-url", $RecursiveBaseUrl,
        "--hook-coverage-dir", $hookCoverageDir,
        "--timeout", "$RecursiveValidationTimeoutSeconds"
    )
    foreach ($inputFile in $inputFiles) {
        $recursiveArgs += @("--input-file", "$inputFile")
    }

    Write-Host "Mode recursive step 2/4: recursive validation enabled"
    Write-Host "Running recursive child-hook seed generation:"
    Write-Host ("  " + (Format-ArgumentCommand -Command "python" -Arguments $recursiveArgs))

    if ($DryRun) {
        exit 0
    }

    foreach ($inputFile in $inputFiles) {
        if (-not (Test-Path -LiteralPath $inputFile)) {
            throw "Missing recursive input file: $inputFile"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $hookCoverageDir "requests"))) {
        throw "Missing hook coverage requests directory: $hookCoverageDir\requests"
    }

    try {
        if ([string]::IsNullOrWhiteSpace($RecursiveHookCoverageDir) -and -not $PSBoundParameters.ContainsKey("RecursiveInputFile")) {
            Write-Host "Mode recursive step 3/4: syncing new request artifacts during replay"
            $syncJob = Start-ArtifactSyncJob -CoverageDir $hookCoverageDir
        } else {
            Write-Host "Mode recursive step 3/4: using provided hook coverage directory"
        }

        python @recursiveArgs
        $recursiveExitCode = $LASTEXITCODE
    } finally {
        if ($syncJob) {
            Stop-Job -Job $syncJob -ErrorAction SilentlyContinue
            Remove-Job -Job $syncJob -Force -ErrorAction SilentlyContinue
        }
    }
    if ($recursiveExitCode -ne $null -and $recursiveExitCode -ne 0) {
        exit $recursiveExitCode
    }

    Write-Host "Mode recursive step 4/4: finished"
    Write-Host "Recursive child-hook artifacts:"
    Write-Host "  $outputDir"
    Write-RecursiveSummary -OutputDir $outputDir
}

function Write-RecursiveSummary {
    param([string]$OutputDir)

    $reportPath = Join-Path $OutputDir "recursive_child_hook_seeds.json"
    if (-not (Test-Path -LiteralPath $reportPath)) {
        Write-Warning "Recursive summary missing: $reportPath"
        return
    }

    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $summary = $report.summary
    Write-Host ("Recursive summary: generated={0}, manual_analysis={1}, duplicates_skipped={2}, depth_skipped={3}" -f `
        $summary.generated, $summary.manual_analysis, $summary.duplicates_skipped, $summary.depth_skipped)

    $observed = [int]$summary.generated + [int]$summary.manual_analysis + [int]$summary.duplicates_skipped + [int]$summary.depth_skipped
    if ($observed -eq 0) {
        Write-Warning "No child-hook metadata found in copied request artifacts. Nothing new can be generated for this run."
    }
}

function Invoke-RecursiveSeedConfigSetup {
    $setupParams = [ordered]@{
        PluginSlug = $PluginSlug
        WebTimeoutSeconds = $WebTimeoutSeconds
        SeedWaitSeconds = $SeedWaitSeconds
        NoFollowLogs = $true
    }
    if ($ForcePlugins) {
        $setupParams["ForcePlugins"] = $true
    }

    Write-Host "Mode recursive step 0/4: preparing selected plugin artifacts"
    Write-Host "Delegating to WordPress PHUZZ runner:"
    Write-Host ("  " + (Format-Command -CommandPath $runnerPath -Parameters $setupParams))

    if ($DryRun) {
        return
    }

    & $runnerPath @setupParams
    if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if ($Help) {
    Show-Usage
    exit 0
}

if (-not (Test-Path -LiteralPath $runnerPath)) {
    throw "Missing WordPress PHUZZ runner: $runnerPath"
}

$interactive = -not $PSBoundParameters.ContainsKey("Mode")
if ($interactive) {
    $Mode = Read-MenuMode
}

if (-not $PSBoundParameters.ContainsKey("PluginSlug")) {
    if ($interactive) {
        $PluginSlug = Read-PluginSlug
    } else {
        $PluginSlug = "show-all-comments-in-one-page"
    }
}

if ($Mode -eq "recursive") {
    if (-not (Test-Path -LiteralPath $recursiveHelperPath)) {
        throw "Missing recursive child-hook helper: $recursiveHelperPath"
    }
    if (-not $PSBoundParameters.ContainsKey("RecursiveInputFile")) {
        Invoke-RecursiveSeedConfigSetup
    }
    Invoke-RecursiveChildHookMode
    exit 0
}

if ($interactive -and -not $PSBoundParameters.ContainsKey("NoFollowLogs")) {
    $followLogs = Read-YesNo -Prompt "Follow fuzzer logs after startup" -Default ($Mode -eq "default")
    $NoFollowLogs = -not $followLogs
}

$runnerParams = [ordered]@{
    PluginSlug = $PluginSlug
    WebTimeoutSeconds = $WebTimeoutSeconds
    SeedWaitSeconds = $SeedWaitSeconds
}
if ($ForcePlugins) {
    $runnerParams["ForcePlugins"] = $true
}
if ($NoFollowLogs) {
    $runnerParams["NoFollowLogs"] = $true
}

switch ($Mode) {
    "default" {
    }
    "seed-config" {
        $runnerParams["NoFollowLogs"] = $true
    }
    "generated" {
        $runnerParams["RunGeneratedConfigs"] = $true
        $runnerParams["GeneratedConfigTimeoutSeconds"] = $GeneratedConfigTimeoutSeconds
    }
    default {
        throw "Unsupported mode '$Mode'."
    }
}

Write-Host "Delegating to WordPress PHUZZ runner:"
Write-Host ("  " + (Format-Command -CommandPath $runnerPath -Parameters $runnerParams))

if ($DryRun) {
    exit 0
}

& $runnerPath @runnerParams
if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
