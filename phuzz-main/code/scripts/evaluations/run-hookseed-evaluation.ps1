param(
    [int]$GamiPressSeconds = 180,
    [int]$CscaSeconds = 180,
    [int]$WebTimeoutSeconds = 240,
    [int]$SeedWaitSeconds = 60,
    [string]$OutputRoot = "fuzzer\output\evaluations",
    [switch]$SkipDownload,
    [switch]$TearDownAfterRun
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$pluginZipRoot = Join-Path $scriptRoot "web\applications\wordpress\_plugins"
$exportCli = Join-Path $scriptRoot "fuzzer\hook_energy\seed_generation\export_cli.py"
$summaryCli = Join-Path $scriptRoot "fuzzer\benchmarking\summary.py"
$localFuzzerOutputDir = Join-Path $scriptRoot "fuzzer\output\fuzzer-1"
$webUrl = "http://localhost:8080/"
$fuzzerService = "fuzzer-wordpress-plugin"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$evaluationRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) { $OutputRoot } else { Join-Path $scriptRoot $OutputRoot }
$evaluationRoot = Join-Path $evaluationRoot $timestamp
$sourceRoot = Join-Path $evaluationRoot "source"
$configRoot = Join-Path $evaluationRoot "configs"
$summaryRows = New-Object System.Collections.Generic.List[object]

New-Item -ItemType Directory -Force -Path $evaluationRoot, $sourceRoot, $configRoot | Out-Null

$pluginDownloads = @(
    @{
        File = "gamipress.zip"
        Url = "https://downloads.wordpress.org/plugin/gamipress.7.3.1.zip"
        SourceDir = "gamipress"
    },
    @{
        File = "country-state-city-auto-dropdown.zip"
        Url = "https://downloads.wordpress.org/plugin/country-state-city-auto-dropdown.2.7.2.zip"
        SourceDir = "country-state-city-auto-dropdown"
    },
    @{
        File = "contact-form-7.zip"
        Url = "https://downloads.wordpress.org/plugin/contact-form-7.5.7.7.zip"
        SourceDir = "contact-form-7"
    }
)

function Invoke-Compose {
    param(
        [string[]]$ComposeArgs,
        [string[]]$AdditionalArgs
    )

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] @AdditionalArgs 2>&1 | ForEach-Object { Write-Host $_ }
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldErrorActionPreference
    if ($exitCode -ne 0) {
        throw "docker compose command failed: $($AdditionalArgs -join ' ')"
    }
}

function Wait-ForWebReady {
    param([string]$Url, [int]$TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
        }
        Start-Sleep -Seconds 5
    }
    throw "Timed out waiting for $Url within $TimeoutSeconds seconds."
}

function Get-ContainerId {
    param([string[]]$ComposeArgs, [string]$ServiceName)

    return (& $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] ps -q $ServiceName).Trim()
}

function Assert-ServiceRunning {
    param([string[]]$ComposeArgs, [string]$ServiceName)

    $containerId = Get-ContainerId -ComposeArgs $ComposeArgs -ServiceName $ServiceName
    if (-not $containerId) {
        throw "Could not resolve container id for $ServiceName."
    }
    $status = (docker inspect -f "{{.State.Status}}" $containerId).Trim()
    if ($status -ne "running") {
        throw "Service $ServiceName status is $status."
    }
}

function Save-Text {
    param([string]$Path, [string[]]$Lines)
    Set-Content -LiteralPath $Path -Value $Lines -Encoding ASCII
}

function Ensure-PluginZip {
    param([hashtable]$Download)

    $zipPath = Join-Path $pluginZipRoot $Download.File
    if ((Test-Path -LiteralPath $zipPath) -and -not $SkipDownload) {
        Remove-Item -Force -LiteralPath $zipPath
    }
    if (-not (Test-Path -LiteralPath $zipPath)) {
        if ($SkipDownload) {
            throw "Missing $zipPath and -SkipDownload was set."
        }
        Invoke-WebRequest -Uri $Download.Url -OutFile $zipPath -UseBasicParsing -TimeoutSec 180
    }

    $extractDir = Join-Path $sourceRoot $Download.SourceDir
    if (Test-Path -LiteralPath $extractDir) {
        Remove-Item -Recurse -Force -LiteralPath $extractDir
    }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $sourceRoot -Force

    return $zipPath
}

function New-OverrideFile {
    param([string]$PluginSlug, [string]$ConfigPath)

    $path = Join-Path $evaluationRoot ("compose-{0}.override.yml" -f $PluginSlug)
    $lines = @(
        "services:",
        "  web:",
        "    environment:",
        "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/$PluginSlug/",
        "      WP_TARGET_PLUGIN: $PluginSlug",
        "  ${fuzzerService}:",
        "    environment:",
        "      FUZZER_CONFIG: $ConfigPath"
    )
    Save-Text -Path $path -Lines $lines
    return $path
}

function Clear-RunState {
    param([string]$WebContainerId)

    if (Test-Path -LiteralPath $localFuzzerOutputDir) {
        $resolved = (Resolve-Path -LiteralPath $localFuzzerOutputDir).Path
        if (-not $resolved.StartsWith((Join-Path $scriptRoot "fuzzer\output"), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clear unexpected path: $resolved"
        }
        Remove-Item -Recurse -Force -LiteralPath $resolved
    }
    docker exec $WebContainerId sh -lc "rm -rf /shared-tmpfs/hook-coverage/requests/* /shared-tmpfs/mysql-error-reports/* /shared-tmpfs/error-reports/*" | Out-Null
}

function Copy-RunArtifacts {
    param(
        [string[]]$ComposeArgs,
        [string]$RunDir,
        [string]$WebContainerId
    )

    $requestsDir = Join-Path $RunDir "requests"
    $fuzzerOutputCopy = Join-Path $RunDir "fuzzer-output"
    New-Item -ItemType Directory -Force -Path $requestsDir, $fuzzerOutputCopy | Out-Null
    if (Test-Path -LiteralPath $localFuzzerOutputDir) {
        Copy-Item -Recurse -Force -Path (Join-Path $localFuzzerOutputDir "*") -Destination $fuzzerOutputCopy -ErrorAction SilentlyContinue
    }
    docker cp "${WebContainerId}:/shared-tmpfs/hook-coverage/requests/." $requestsDir | Out-Null
    docker cp "${WebContainerId}:/shared-tmpfs/hook-coverage/total_coverage.json" (Join-Path $RunDir "total_coverage.json") | Out-Null
    $lines = & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] logs $fuzzerService --tail=400
    if ($LASTEXITCODE -eq 0) {
        Set-Content -LiteralPath (Join-Path $RunDir "fuzzer.log") -Value $lines -Encoding UTF8
    }
}

function Convert-SeedToConfig {
    param(
        [object]$SeedItem,
        [string]$OutputPath
    )

    $seed = $SeedItem.seed
    $bodyData = New-Object System.Collections.Generic.List[object]
    foreach ($prop in $seed.body.PSObject.Properties) {
        $bodyData.Add(@{ name = $prop.Name; value = [string]$prop.Value })
    }
    $queryData = New-Object System.Collections.Generic.List[object]
    foreach ($prop in $seed.query_params.PSObject.Properties) {
        $queryData.Add(@{ name = $prop.Name; value = [string]$prop.Value })
    }

    $config = @{
        target = "http://web$($seed.path)"
        methods = @($seed.method)
        print_timestamps = $true
    }
    if ($bodyData.Count -gt 0) {
        $config["body_params"] = @{
            data = $bodyData.ToArray()
            fixed = [string[]]@($seed.fixed_params)
            fuzz = [string[]]@($seed.fuzzable_params)
            weight = 1
        }
    }
    if ($queryData.Count -gt 0) {
        $config["query_params"] = @{
            data = $queryData.ToArray()
            fixed = @()
            fuzz = [string[]]@($seed.fuzzable_params)
            weight = 1
        }
    }

    $config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding ASCII
}

function Test-CallbackReached {
    param([string]$RunDir, [string]$CallbackId)

    foreach ($path in Get-ChildItem -LiteralPath (Join-Path $RunDir "requests") -Filter "*.json" -File -ErrorAction SilentlyContinue) {
        $payload = Get-Content -LiteralPath $path.FullName -Raw | ConvertFrom-Json
        $executed = $payload.hook_coverage.executed_callbacks
        if ($null -eq $executed) {
            continue
        }
        if ($executed.PSObject.Properties.Name -contains $CallbackId) {
            return $true
        }
    }
    return $false
}

function Test-ParamMutated {
    param([string]$RunDir, [string]$ParamName)

    $candidateFiles = @("vulnerable-candidates.json", "exceptions-and-errors.json")
    foreach ($file in $candidateFiles) {
        $path = Join-Path $RunDir "fuzzer-output\$file"
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }
        $raw = Get-Content -LiteralPath $path -Raw
        if ($raw -match ('"mutated_param_name"\s*:\s*"' + [regex]::Escape($ParamName) + '"')) {
            return $true
        }
    }

    foreach ($path in Get-ChildItem -LiteralPath (Join-Path $RunDir "requests") -Filter "*.json" -File -ErrorAction SilentlyContinue) {
        $raw = Get-Content -LiteralPath $path.FullName -Raw
        if ($raw -match ('"' + [regex]::Escape($ParamName) + '"\s*:\s*"(?!FUZZ")')) {
            return $true
        }
    }
    return $false
}

function Export-Seeds {
    param(
        [string]$PluginSlug,
        [string[]]$ComposeArgs,
        [string]$HostPluginRoot
    )

    $webContainerId = Get-ContainerId -ComposeArgs $ComposeArgs -ServiceName "web"
    if (-not $webContainerId) {
        throw "Could not resolve web container for $PluginSlug."
    }

    $deadline = (Get-Date).AddSeconds($SeedWaitSeconds)
    $coverageFile = Join-Path $evaluationRoot "$PluginSlug-total_coverage.json"
    while ((Get-Date) -lt $deadline) {
        Invoke-WebRequest -Uri $webUrl -UseBasicParsing -TimeoutSec 10 | Out-Null
        docker cp "${webContainerId}:/shared-tmpfs/hook-coverage/total_coverage.json" $coverageFile 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $coverageFile)) {
            break
        }
        Start-Sleep -Seconds 5
    }
    if (-not (Test-Path -LiteralPath $coverageFile)) {
        throw "No total_coverage.json observed for $PluginSlug."
    }

    $seedDir = Join-Path $evaluationRoot "$PluginSlug-seeds"
    $exportOutput = & python $exportCli `
        --coverage-file $coverageFile `
        --output-dir $seedDir `
        --container-source-root "/var/www/html/wp-content/plugins/$PluginSlug" `
        --host-source-root $HostPluginRoot `
        --source-root $HostPluginRoot 2>&1
    $exportOutput | Set-Content -LiteralPath (Join-Path $seedDir "export.log") -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        throw "Seed export failed for $PluginSlug."
    }
    return $seedDir
}

function Find-Seed {
    param([string]$SeedDir, [string]$HookName)

    $payload = Get-Content -LiteralPath (Join-Path $SeedDir "suggested_seeds.json") -Raw | ConvertFrom-Json
    foreach ($item in $payload.suggested_seeds) {
        if ($item.hook_name -eq $HookName) {
            return $item
        }
    }
    throw "Could not find seed for $HookName in $SeedDir."
}

function Invoke-SeedFuzz {
    param(
        [string]$PluginSlug,
        [string]$HookName,
        [object]$SeedItem,
        [string[]]$ComposeArgs,
        [int]$Seconds
    )

    $safeHook = $HookName -replace '[^A-Za-z0-9_.-]', '_'
    $runDir = Join-Path $evaluationRoot "$PluginSlug-$safeHook-run"
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $configPath = Join-Path $configRoot "$PluginSlug-$safeHook.json"
    Convert-SeedToConfig -SeedItem $SeedItem -OutputPath $configPath
    $relativeConfig = "../output/evaluations/$timestamp/configs/$PluginSlug-$safeHook"
    $overridePath = New-OverrideFile -PluginSlug $PluginSlug -ConfigPath $relativeConfig
    $runComposeArgs = @("docker", "compose", "-f", "docker-compose.yml", "-f", $overridePath)

    $webContainerId = Get-ContainerId -ComposeArgs $ComposeArgs -ServiceName "web"
    Clear-RunState -WebContainerId $webContainerId
    Invoke-Compose -ComposeArgs $runComposeArgs -AdditionalArgs @("up", "-d", $fuzzerService, "--build", "--force-recreate")
    Assert-ServiceRunning -ComposeArgs $runComposeArgs -ServiceName $fuzzerService
    Start-Sleep -Seconds $Seconds
    Copy-RunArtifacts -ComposeArgs $runComposeArgs -RunDir $runDir -WebContainerId $webContainerId
    Invoke-Compose -ComposeArgs $runComposeArgs -AdditionalArgs @("stop", $fuzzerService)

    $summaryOutput = & python $summaryCli summarize-run `
        --run-dir $runDir `
        --plugin $PluginSlug `
        --mode-label "PHUZZ_GENERATED_SEED" `
        --mode-value 1 `
        --run-id 1 `
        --time-budget-seconds $Seconds `
        --output (Join-Path $runDir "benchmark_summary.json") 2>&1
    $summaryOutput | Set-Content -LiteralPath (Join-Path $runDir "summary.log") -Encoding UTF8
    if ($LASTEXITCODE -ne 0) {
        throw "Run summary failed for $HookName."
    }

    return $runDir
}

function Add-EvaluationRow {
    param(
        [string]$PluginSlug,
        [string]$HookName,
        [string]$ParamName,
        [object]$SeedItem,
        [string]$RunDir
    )

    $summary = Get-Content -LiteralPath (Join-Path $RunDir "benchmark_summary.json") -Raw | ConvertFrom-Json
    $seed = $SeedItem.seed
    $vulnExists = Test-Path -LiteralPath (Join-Path $RunDir "fuzzer-output\vulnerable-candidates.json")
    $summaryRows.Add([ordered]@{
        plugin = $PluginSlug
        hook = $HookName
        param = $ParamName
        seed_generated_automatically = $true
        fuzzable_param_discovered_automatically = @($seed.fuzzable_params) -contains $ParamName
        callback_reached = $summary.unique_executed_callbacks -gt 0
        requests_sent = $summary.total_requests
        vulnerability_found = @($summary.unique_vuln_signatures).Count -gt 0
        generated_callback_id = $SeedItem.callback_id
        generated_callback_reached = Test-CallbackReached -RunDir $RunDir -CallbackId $SeedItem.callback_id
        param_mutated = Test-ParamMutated -RunDir $RunDir -ParamName $ParamName
        time_to_first_vulnerability_seconds = $summary.time_to_first_unique_vuln_seconds
        requests_to_first_vulnerability = $summary.requests_to_first_unique_vuln
        benign_errors_filtered = $summary.filtered_benign_errors
        vulnerability_relevant_errors = $summary.vulnerability_relevant_errors
        vulnerable_candidates_json_exists = $vulnExists
        manual_config_effort_reduced = "action/path/param seed config generated from runtime hook artifact"
        run_dir = $RunDir
    }) | Out-Null
}

Push-Location $scriptRoot
try {
    foreach ($download in $pluginDownloads) {
        Ensure-PluginZip -Download $download | Out-Null
    }

    $targets = @(
        @{
            Slug = "gamipress"
            HostRoot = Join-Path $sourceRoot "gamipress"
            Hooks = @(@{ Name = "wp_ajax_nopriv_gamipress_get_logs"; Param = "orderby"; Seconds = $GamiPressSeconds })
        },
        @{
            Slug = "country-state-city-auto-dropdown"
            HostRoot = Join-Path $sourceRoot "country-state-city-auto-dropdown"
            Hooks = @(
                @{ Name = "wp_ajax_nopriv_tc_csca_get_cities"; Param = "sid"; Seconds = $CscaSeconds },
                @{ Name = "wp_ajax_nopriv_tc_csca_get_states"; Param = "cnt"; Seconds = $CscaSeconds }
            )
        }
    )

    foreach ($target in $targets) {
        $bootstrapOverride = New-OverrideFile -PluginSlug $target.Slug -ConfigPath "wordpress/show-all-comments-in-one-page"
        $composeArgs = @("docker", "compose", "-f", "docker-compose.yml", "-f", $bootstrapOverride)
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("down", "--volumes", "--remove-orphans")
        Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @("up", "-d", "db", "web", "--build")
        Wait-ForWebReady -Url $webUrl -TimeoutSeconds $WebTimeoutSeconds
        $seedDir = Export-Seeds -PluginSlug $target.Slug -ComposeArgs $composeArgs -HostPluginRoot $target.HostRoot

        foreach ($hook in $target.Hooks) {
            $seedItem = Find-Seed -SeedDir $seedDir -HookName $hook.Name
            $runDir = Invoke-SeedFuzz -PluginSlug $target.Slug -HookName $hook.Name -SeedItem $seedItem -ComposeArgs $composeArgs -Seconds $hook.Seconds
            Add-EvaluationRow -PluginSlug $target.Slug -HookName $hook.Name -ParamName $hook.Param -SeedItem $seedItem -RunDir $runDir
        }
    }

    $jsonPath = Join-Path $evaluationRoot "evaluation-summary.json"
    $csvPath = Join-Path $evaluationRoot "evaluation-summary.csv"
    $mdPath = Join-Path $evaluationRoot "evaluation-summary.md"
    $summaryRows | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $summaryRows | ForEach-Object { [pscustomobject]$_ } | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $lines = @(
        "| Plugin | Hook | Param | Seed auto | Param auto | Callback reached | Requests | Vuln found | Time to first vuln | Requests to first vuln | Benign filtered | Relevant errors |",
        "| --- | --- | --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: |"
    )
    foreach ($row in $summaryRows) {
        $lines += "| $($row.plugin) | $($row.hook) | $($row.param) | $($row.seed_generated_automatically) | $($row.fuzzable_param_discovered_automatically) | $($row.callback_reached) | $($row.requests_sent) | $($row.vulnerability_found) | $($row.time_to_first_vulnerability_seconds) | $($row.requests_to_first_vulnerability) | $($row.benign_errors_filtered) | $($row.vulnerability_relevant_errors) |"
    }
    Set-Content -LiteralPath $mdPath -Value $lines -Encoding UTF8

    Write-Host "Evaluation artifacts written to: $evaluationRoot"
} finally {
    if ($TearDownAfterRun) {
        docker compose down --volumes --remove-orphans
    }
    Pop-Location
}
