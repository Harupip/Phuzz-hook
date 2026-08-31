param(
    [ValidateSet("default", "seed-config", "generated", "zend", "online", "online-linked", "recursive")]
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
    [ValidateRange(1, 30)]
    [int]$GeneratedConfigTimeoutSeconds = 30,
    [switch]$UseEntrypointPipeline,
    [switch]$UseZendDiscovery,
    [switch]$KeepDebugArtifacts,
    [ValidateRange(1, 30)]
    [int]$ZendMaxIterations = 5,
    [ValidateRange(1, 60)]
    [int]$OnlineTimeoutSeconds = 60,
    [ValidateRange(1, 20)]
    [int]$OnlineMaxVersions = 2,
    [ValidateRange(1, 20)]
    [int]$MaxHookDepth = 3,
    [ValidateRange(1, 300)]
    [int]$RecursiveValidationTimeoutSeconds = 10,
    [switch]$RunRecursiveConfigs,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$runnerPath = Join-Path $scriptRoot "scripts\wordpress\run-wordpress-phuzz.ps1"
$recursiveHelperPath = Join-Path $scriptRoot "fuzzer\hook_energy\recursive_child_hook_seeds.py"
$generatedConfigRunnerPath = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\generated_config_runner.py"
$pluginDir = Join-Path $scriptRoot "web\applications\wordpress\_plugins"
$configDir = Join-Path $scriptRoot "fuzzer\configs\wordpress"

function Show-Usage {
    Write-Host @"
Guided PHUZZ runner

Usage:
  .\phuzz.ps1
  .\phuzz.ps1 -Mode default
  .\phuzz.ps1 -Mode seed-config -NoFollowLogs
  .\phuzz.ps1 -Mode generated -PluginSlug gamipress -GeneratedConfigTimeoutSeconds 30 -NoFollowLogs
  .\phuzz.ps1 -Mode zend -PluginSlug gamipress -ZendMaxIterations 5 -GeneratedConfigTimeoutSeconds 30 -NoFollowLogs
  .\phuzz.ps1 -Mode recursive
  .\phuzz.ps1 -Mode recursive -RunRecursiveConfigs
  .\phuzz.ps1 -Mode online -PluginSlug hookphuzz-entrypoint-direct-fixture -UseZendDiscovery -OnlineTimeoutSeconds 60 -OnlineMaxVersions 2 -NoFollowLogs
  .\phuzz.ps1 -Mode online-linked -PluginSlug hookphuzz-online-discovery-fixture -UseZendDiscovery -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3 -NoFollowLogs
  .\phuzz.ps1 -Mode recursive -RecursiveInputFile fuzzer\output\hook-coverage\requests\latest.json
  .\phuzz.ps1 -Mode generated -GeneratedConfigTimeoutSeconds 30 -NoFollowLogs -DryRun

Modes:
  default      Start WordPress PHUZZ with existing behavior.
  seed-config  Start WordPress, export hook seeds, generate PHUZZ configs, do not follow logs.
  generated    Export seeds/configs, then run generated hook configs sequentially.
  zend         Run generated configs with runtime-only Zend parameter discovery.
  online       Start bounded v0 fuzzing, then replay-gate immutable Zend-discovered child workers.
  online-linked Start immutable versioned workers, replay-gating Zend-discovered child workers.
  recursive    Generate recursive child-hook seeds/configs from request artifacts.

Useful options:
  -PluginSlug <slug>               WordPress plugin ZIP/config slug. Default: show-all-comments-in-one-page.
  -ForcePlugins                    Re-download the default plugin ZIP when using the default target.
  -NoFollowLogs                    Return after startup instead of following fuzzer logs.
  -WebTimeoutSeconds <seconds>     Wait window for WordPress HTTP 200. Default: 240.
  -SeedWaitSeconds <seconds>       Wait window for live hook coverage snapshot. Default: 45.
  -GeneratedConfigTimeoutSeconds   Per generated-config run window. Default/max: 30.
  -UseEntrypointPipeline           Opt-in generated mode to the entrypoint pipeline.
  -UseZendDiscovery                Opt-in online/online-linked mode to runtime-only Zend parameter discovery; use -Mode zend for generated discovery.
  -KeepDebugArtifacts              Keep Zend intermediate artifacts after a successful run.
  -ZendMaxIterations <count>       Max Zend REST convergence iterations. Default: 5.
  -OnlineTimeoutSeconds <seconds>  Bounded online discovery budget. Default/max: 60.
  -OnlineMaxVersions <count>       Maximum online config versions including v0. Default: 2.
  -RecursiveInputFile <path>       Child-hook input artifact. Repeat for multiple files.
  -RecursiveHookCoverageDir <path> Hook coverage dir with requests/ for recursive validation.
  -RecursiveBaseUrl <url>          WordPress base URL for recursive validation. Default: http://localhost:8080.
  -MaxHookDepth <depth>            Recursive child-hook depth. Default: 3.
  -RecursiveValidationTimeoutSeconds <seconds> Per child-hook replay timeout. Default: 10.
  -RunRecursiveConfigs             Run recursive generated configs after recursive discovery.
  -DryRun                          Print the delegated command without running it.
"@
}

function Get-LocalPluginSlugs {
    param([bool]$RequireConfig = $true)

    if (-not (Test-Path -LiteralPath $pluginDir)) {
        return @()
    }

    return @(
        Get-ChildItem -LiteralPath $pluginDir -Filter "*.zip" |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) } |
            Where-Object { (-not $RequireConfig) -or (Test-Path -LiteralPath (Join-Path $configDir "$_.json")) } |
            Sort-Object -Unique
    )
}

function Read-MenuMode {
    Write-Host ""
    Write-Host "Choose PHUZZ workflow:"
    Write-Host "  1) default     - Start WordPress PHUZZ with existing behavior"
    Write-Host "  2) seed-config - Start web, export hook seeds, generate PHUZZ configs"
    Write-Host "  3) generated   - Generate configs, then run them sequentially"
    Write-Host "  4) zend        - Generated configs with runtime-only Zend parameter discovery"
    Write-Host "  5) online      - Bounded v0 fuzzing with Zend-discovered child workers"
    Write-Host "  6) recursive   - Generate recursive child-hook seeds/configs from request artifacts"

    $choice = (Read-Host "Select [1-6]").Trim()
    switch ($choice) {
        "1" { return "default" }
        "2" { return "seed-config" }
        "3" { return "generated" }
        "4" { return "zend" }
        "5" { return "online" }
        "6" { return "recursive" }
        default { throw "Invalid selection '$choice'. Choose 1, 2, 3, 4, 5, or 6." }
    }
}

function Read-PluginSlug {
    param([bool]$RequireConfig = $true)

    $slugs = @(Get-LocalPluginSlugs -RequireConfig $RequireConfig)
    if ($slugs.Count -eq 0) {
        Write-Host "No local plugin ZIP found. Using default: show-all-comments-in-one-page"
        return "show-all-comments-in-one-page"
    }

    Write-Host ""
    if ($RequireConfig) {
        Write-Host "Choose local WordPress plugin with matching PHUZZ config:"
    } else {
        Write-Host "Choose local WordPress plugin:"
    }
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

function Clear-RecursiveContainerArtifacts {
    $requestsDir = "/shared-tmpfs/hook-coverage/requests"

    Write-Host "Cleaning recursive hook coverage artifacts"
    Write-Host "  docker compose stop --timeout 30 fuzzer-wordpress-plugin"
    docker compose stop --timeout 30 fuzzer-wordpress-plugin | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not stop fuzzer-wordpress-plugin before recursive artifact cleanup."
        return
    }

    docker compose exec -T web sh -lc "find $requestsDir -maxdepth 1 -type f -delete" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not clean recursive hook coverage artifacts from web:$requestsDir"
    }
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
    $copiedContainerArtifacts = $false

    Write-Host "Mode recursive step 1/4: preparing request artifacts"
    if ($inputFiles.Count -eq 0 -and -not $DryRun) {
        Write-RecursiveContainerTarget
        $copyResult = Copy-ContainerRequestArtifacts -OutputDir $outputDir
        $inputFiles = @($copyResult.InputFiles)
        $hookCoverageDir = $copyResult.CoverageDir
        $copiedContainerArtifacts = $true
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
    $recursiveConfigRunnerArgs = @(Get-RecursiveConfigRunnerArgs -OutputDir $outputDir)
    if ($RunRecursiveConfigs) {
        Write-Host "Running recursive generated configs:"
        Write-Host ("  " + (Format-ArgumentCommand -Command "python" -Arguments $recursiveConfigRunnerArgs))
    }

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
        if ($copiedContainerArtifacts -and -not $RunRecursiveConfigs) {
            Clear-RecursiveContainerArtifacts
        }
    }
    if ($recursiveExitCode -ne $null -and $recursiveExitCode -ne 0 -and -not $RunRecursiveConfigs) {
        exit $recursiveExitCode
    }
    if ($recursiveExitCode -ne $null -and $recursiveExitCode -ne 0) {
        Write-Warning "Recursive seed validation failed; continuing to recursive config runner because -RunRecursiveConfigs is set."
    }

    Write-Host "Recursive child-hook artifacts:"
    Write-Host "  $outputDir"
    Write-RecursiveSummary -OutputDir $outputDir
    if ($RunRecursiveConfigs) {
        Write-Host "Mode recursive step 4/4: running recursive generated configs"
        $recursiveConfigExitCode = Invoke-RecursiveConfigRunner -OutputDir $outputDir -RunnerArgs $recursiveConfigRunnerArgs
        if ($recursiveConfigExitCode -ne 0) {
            exit $recursiveConfigExitCode
        }
    }
    Write-Host "Mode recursive step 4/4: finished"
}

function Get-RecursiveConfigRunnerArgs {
    param([string]$OutputDir)

    return @(
        $generatedConfigRunnerPath,
        "--generated-config-summary", (Join-Path $OutputDir "generated_config_summary.json"),
        "--output-file", (Join-Path $OutputDir "recursive_config_run_summary.json"),
        "--timeout-seconds", "$GeneratedConfigTimeoutSeconds",
        "--output-format", "recursive"
    )
}

function Invoke-RecursiveConfigRunner {
    param(
        [string]$OutputDir,
        [string[]]$RunnerArgs
    )

    if (-not (Test-Path -LiteralPath $generatedConfigRunnerPath)) {
        throw "Missing generated config runner: $generatedConfigRunnerPath"
    }

    Write-Host "Stopping default fuzzer before recursive config batch"
    docker compose stop --timeout 30 fuzzer-wordpress-plugin | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not stop fuzzer-wordpress-plugin before recursive config batch."
    }

    python @RunnerArgs
    $runnerExitCode = $LASTEXITCODE

    $runSummaryPath = Join-Path $OutputDir "recursive_config_run_summary.json"
    if (-not (Test-Path -LiteralPath $runSummaryPath)) {
        throw "Recursive config runner did not create summary: $runSummaryPath"
    }

    $seedValidation = Get-RecursiveSeedValidationSummary -OutputDir $OutputDir
    $result = Update-RecursiveConfigRunSummary -SummaryPath $runSummaryPath -SeedValidation $seedValidation -RunnerExitCode $runnerExitCode
    Write-Host ("Recursive e2e summary: seed_validation_status={0}, seed_validation_failed_count={1}, config_runner_status={2}, overall_e2e_status={3}" -f `
        $result.SeedValidationStatus, $result.SeedValidationFailedCount, $result.ConfigRunnerStatus, $result.OverallE2eStatus)

    if (-not $result.Success) {
        return 1
    }
    return 0
}

function Get-RecursiveSeedValidationSummary {
    param([string]$OutputDir)

    $validationPath = Join-Path $OutputDir "validation_result.json"
    if (-not (Test-Path -LiteralPath $validationPath)) {
        return [pscustomobject]@{
            Status = "missing"
            FailedCount = 0
        }
    }

    $validation = Get-Content -LiteralPath $validationPath -Raw | ConvertFrom-Json
    $summary = $validation.summary
    $total = Get-JsonInt -Object $summary -Name "total" -Default @($validation.validations).Count
    $reached = Get-JsonInt -Object $summary -Name "callback_reached" -Default 0
    $failedCount = [Math]::Max(0, $total - $reached)
    $status = if ($total -eq 0) { "not_run" } elseif ($failedCount -eq 0) { "passed" } else { "failed" }

    return [pscustomobject]@{
        Status = $status
        FailedCount = $failedCount
    }
}

function Update-RecursiveConfigRunSummary {
    param(
        [string]$SummaryPath,
        [object]$SeedValidation,
        [int]$RunnerExitCode
    )

    $summary = Get-Content -LiteralPath $SummaryPath -Raw | ConvertFrom-Json
    $results = @($summary.results)
    $callbackReached = @($results | Where-Object { $_.status -eq "callback_reached" }).Count
    $runnerError = Get-JsonInt -Object $summary -Name "runner_error" -Default @($results | Where-Object { $_.status -eq "runner_error" }).Count
    $timedOut = Get-JsonInt -Object $summary -Name "timed_out" -Default 0
    $passed = Get-JsonInt -Object $summary -Name "passed" -Default $callbackReached
    $totalConfigs = Get-JsonInt -Object $summary -Name "total_configs" -Default $results.Count

    $success = (($passed -gt 0 -and $runnerError -eq 0 -and $timedOut -eq 0) -or $callbackReached -gt 0)
    if ($totalConfigs -gt 0 -and $passed -eq 0) {
        $success = $false
    }

    if ($success) {
        $configRunnerStatus = "passed"
    } elseif ($runnerError -gt 0) {
        $configRunnerStatus = "runner_error"
    } elseif ($timedOut -gt 0) {
        $configRunnerStatus = "timed_out"
    } elseif ($totalConfigs -gt 0 -and $passed -eq 0) {
        $configRunnerStatus = "failed_no_callback_reached"
    } else {
        $configRunnerStatus = "failed"
    }

    if ($success -and $SeedValidation.FailedCount -gt 0) {
        $overallStatus = "passed_with_seed_validation_warning"
    } elseif ($success) {
        $overallStatus = "passed_config_runner"
    } else {
        $overallStatus = "failed_config_runner"
    }

    Set-JsonProperty -Object $summary -Name "seed_validation_status" -Value $SeedValidation.Status
    Set-JsonProperty -Object $summary -Name "seed_validation_failed_count" -Value $SeedValidation.FailedCount
    Set-JsonProperty -Object $summary -Name "config_runner_status" -Value $configRunnerStatus
    Set-JsonProperty -Object $summary -Name "overall_e2e_status" -Value $overallStatus
    Set-JsonProperty -Object $summary -Name "runner_process_exit_code" -Value $RunnerExitCode
    $summary | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

    return [pscustomobject]@{
        Success = $success
        SeedValidationStatus = $SeedValidation.Status
        SeedValidationFailedCount = $SeedValidation.FailedCount
        ConfigRunnerStatus = $configRunnerStatus
        OverallE2eStatus = $overallStatus
    }
}

function Get-JsonInt {
    param(
        [object]$Object,
        [string]$Name,
        [int]$Default = 0
    )

    if ($null -eq $Object) {
        return $Default
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $Default
    }
    try {
        return [int]$property.Value
    } catch {
        return $Default
    }
}

function Set-JsonProperty {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Value
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    } else {
        $property.Value = $Value
    }
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

if ($UseEntrypointPipeline -and $PSBoundParameters.ContainsKey("Mode") -and $Mode -ne "generated") {
    throw "-UseEntrypointPipeline is only supported with -Mode generated."
}
if ($UseZendDiscovery -and $PSBoundParameters.ContainsKey("Mode") -and $Mode -eq "generated") {
    throw "-UseZendDiscovery is now a dedicated -Mode zend workflow. Use -Mode zend instead."
}
if ($UseZendDiscovery -and $PSBoundParameters.ContainsKey("Mode") -and $Mode -notin @("zend", "online", "online-linked")) {
    throw "-UseZendDiscovery is only supported with -Mode zend, -Mode online, or -Mode online-linked."
}

$interactive = -not $PSBoundParameters.ContainsKey("Mode")
if ($interactive) {
    $Mode = Read-MenuMode
}

if ($Mode -eq "zend") {
    $UseZendDiscovery = $true
}
if ($interactive -and $Mode -eq "online") {
    $UseZendDiscovery = $true
}

if ($UseEntrypointPipeline -and $Mode -ne "generated") {
    throw "-UseEntrypointPipeline is only supported with -Mode generated."
}
if ($UseZendDiscovery -and $Mode -eq "generated") {
    throw "-UseZendDiscovery is now a dedicated -Mode zend workflow. Use -Mode zend instead."
}
if ($UseZendDiscovery -and $Mode -notin @("zend", "online", "online-linked")) {
    throw "-UseZendDiscovery is only supported with -Mode zend, -Mode online, or -Mode online-linked."
}

if (-not $PSBoundParameters.ContainsKey("PluginSlug")) {
    if ($interactive) {
        $PluginSlug = Read-PluginSlug -RequireConfig ($Mode -notin @("generated", "zend"))
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

if (-not (Test-Path -LiteralPath $runnerPath)) {
    throw "Missing WordPress PHUZZ runner: $runnerPath"
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
        if ($UseEntrypointPipeline) {
            $runnerParams["UseEntrypointPipeline"] = $true
        }
        if ($KeepDebugArtifacts) {
            $runnerParams["KeepDebugArtifacts"] = $true
        }
    }
    "zend" {
        $runnerParams["RunGeneratedConfigs"] = $true
        $runnerParams["GeneratedConfigTimeoutSeconds"] = $GeneratedConfigTimeoutSeconds
        $runnerParams["UseZendDiscovery"] = $true
        $runnerParams["ZendMaxIterations"] = $ZendMaxIterations
        if ($KeepDebugArtifacts) {
            $runnerParams["KeepDebugArtifacts"] = $true
        }
    }
    "online" {
        $runnerParams["RunOnline"] = $true
        $runnerParams["OnlineTimeoutSeconds"] = $OnlineTimeoutSeconds
        $runnerParams["OnlineMaxVersions"] = $OnlineMaxVersions
        if ($UseZendDiscovery) {
            $runnerParams["UseZendDiscovery"] = $true
        }
    }
    "online-linked" {
        $runnerParams["RunOnlineLinked"] = $true
        $runnerParams["OnlineTimeoutSeconds"] = $OnlineTimeoutSeconds
        $runnerParams["OnlineMaxVersions"] = $OnlineMaxVersions
        if ($UseZendDiscovery) {
            $runnerParams["UseZendDiscovery"] = $true
        }
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
