param(
    [ValidateSet("default", "seed-config", "generated", "zend", "online", "online-linked")]
    [string]$Mode,
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug,
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
    [ValidateRange(1, 120)]
    [int]$OnlineTimeoutSeconds = 120,
    [ValidateRange(1, 20)]
    [int]$OnlineMaxVersions = 2,
    [ValidateRange(1, 128)]
    [int]$OnlineMaxCandidates = 32,
    [ValidateRange(1, 86400)]
    [int]$OnlineCampaignTimeoutSeconds = 3600,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$runnerPath = Join-Path $scriptRoot "scripts\wordpress\run-wordpress-phuzz.ps1"
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
  .\phuzz.ps1 -Mode online -PluginSlug hookphuzz-entrypoint-direct-fixture -UseZendDiscovery -OnlineTimeoutSeconds 60 -OnlineMaxVersions 2 -NoFollowLogs
  .\phuzz.ps1 -Mode online-linked -PluginSlug hookphuzz-online-discovery-fixture -UseZendDiscovery -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3 -NoFollowLogs
  .\phuzz.ps1 -Mode generated -GeneratedConfigTimeoutSeconds 30 -NoFollowLogs -DryRun

Modes:
  default      Start WordPress PHUZZ with existing behavior.
  seed-config  Start WordPress, export hook seeds, generate PHUZZ configs, do not follow logs.
  generated    Export seeds/configs, then run generated hook configs sequentially.
  zend         Run generated configs with runtime-only Zend parameter discovery.
  online       Start bounded v0 fuzzing, then replay-gate immutable Zend-discovered child workers.
  online-linked Start immutable versioned workers, replay-gating Zend-discovered child workers.

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
  -OnlineTimeoutSeconds <seconds>  Bounded online discovery budget. Default/max: 120/120.
  -OnlineMaxVersions <count>       Maximum online config versions including v0. Default: 2.
  -OnlineMaxCandidates <count>     Maximum online-linked candidates per campaign. Default: 32.
  -OnlineCampaignTimeoutSeconds    Maximum online-linked campaign budget. Default: 3600.
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
    Write-Host "  6) online-linked - Versioned workers with linked Zend-discovered child workers"

    $choice = (Read-Host "Select [1-6]").Trim()
    switch ($choice) {
        "1" { return "default" }
        "2" { return "seed-config" }
        "3" { return "generated" }
        "4" { return "zend" }
        "5" { return "online" }
        "6" { return "online-linked" }
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
if ($interactive -and $Mode -in @("online", "online-linked")) {
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
        $runnerParams["OnlineMaxCandidates"] = $OnlineMaxCandidates
        $runnerParams["OnlineCampaignTimeoutSeconds"] = $OnlineCampaignTimeoutSeconds
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
