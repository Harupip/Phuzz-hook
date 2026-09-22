function Invoke-OnlineLinked {
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)][string]$PluginSlug,
        [Parameter(Mandatory)][string]$LegacyRunId,
        [Parameter(Mandatory)][string]$SuggestedSeedsPath,
        [Parameter(Mandatory)][string]$BootstrapConfig,
        [Parameter(Mandatory)][string]$CallbackRegistry,
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][int]$OnlineTimeoutSeconds,
        [Parameter(Mandatory)][int]$OnlineMaxVersions,
        [Parameter(Mandatory)][int]$OnlineMaxCandidates,
        [Parameter(Mandatory)][int]$OnlineCampaignTimeoutSeconds,
        [bool]$OnlineComparePrompt = $false,
        [Parameter(Mandatory)][string]$OverridePath,
        [Parameter(Mandatory)][string[]]$ComposeArgs
    )

    $fuzzerRoot = Join-Path $ScriptRoot "fuzzer"
    foreach ($path in @((Join-Path $fuzzerRoot "online_linked\__main__.py"), $SuggestedSeedsPath, $CallbackRegistry)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Missing online-linked input or entrypoint: $path"
        }
    }
    $onlineLinkedArgs = @(
        "-m", "online_linked",
        "--suggested-seeds", $SuggestedSeedsPath,
        "--bootstrap-config", $BootstrapConfig,
        "--config-root", (Join-Path $fuzzerRoot "configs"),
        "--output-root", (Join-Path $fuzzerRoot "output"),
        "--plugin-slug", $PluginSlug,
        "--legacy-run-id", $LegacyRunId,
        "--callback-registry", $CallbackRegistry,
        "--max-seconds", "$OnlineTimeoutSeconds",
        "--max-versions", "$OnlineMaxVersions",
        "--max-candidates", "$OnlineMaxCandidates",
        "--campaign-seconds", "$OnlineCampaignTimeoutSeconds",
        "--sync-registry",
        "--service", $Service
    )

    $previousComposeFile = $env:COMPOSE_FILE
    $previousPythonPath = $env:PYTHONPATH
    Push-Location $ScriptRoot
    try {
        Write-Host "Stopping bootstrap fuzzer before immutable online-linked v0 starts"
        & $ComposeArgs[0] $ComposeArgs[1..($ComposeArgs.Count - 1)] stop --timeout 30 $Service
        if ($LASTEXITCODE -ne 0) {
            throw "Could not stop bootstrap fuzzer before online-linked starts."
        }
        $env:COMPOSE_FILE = "docker-compose.yml;$OverridePath"
        $env:PYTHONPATH = $fuzzerRoot
        if ($previousPythonPath) {
            $env:PYTHONPATH += [IO.Path]::PathSeparator + $previousPythonPath
        }
        Write-Host "Starting bounded online-linked Zend discovery"
        python @onlineLinkedArgs
        $onlineLinkedExitCode = $LASTEXITCODE
    } finally {
        if ($null -eq $previousComposeFile) {
            Remove-Item Env:COMPOSE_FILE -ErrorAction SilentlyContinue
        } else {
            $env:COMPOSE_FILE = $previousComposeFile
        }
        if ($null -eq $previousPythonPath) {
            Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        } else {
            $env:PYTHONPATH = $previousPythonPath
        }
        Pop-Location
    }

    $statePath = Join-Path (Join-Path (Join-Path $fuzzerRoot "output\online-linked") $LegacyRunId) "batch-state.json"
    Write-Host "Online-linked state: $statePath"
    if ($onlineLinkedExitCode -ne 0) {
        throw "Online-linked Zend discovery failed. See $statePath"
    }
    if ($OnlineComparePrompt) {
        Push-Location $ScriptRoot
        try {
            python -m fuzzer.config_comparison.online_linked --prompt-batch (Split-Path -Parent $statePath)
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Config comparison returned exit code $LASTEXITCODE. Online-linked discovery status is unchanged."
            }
        } finally {
            Pop-Location
            $global:LASTEXITCODE = $onlineLinkedExitCode
        }
    }
}
