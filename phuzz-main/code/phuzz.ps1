[CmdletBinding()]
param(
    [ValidateSet("online-linked")]
    [string]$Mode = "online-linked",
    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string]$PluginSlug,
    [switch]$ForcePlugins,
    [switch]$NoFollowLogs,
    [ValidateRange(1, 86400)]
    [int]$WebTimeoutSeconds = 240,
    [ValidateRange(1, 86400)]
    [int]$SeedWaitSeconds = 45,
    [switch]$UseZendDiscovery,
    [ValidateRange(1, 120)]
    [int]$OnlineTimeoutSeconds,
    [ValidateRange(1, 20)]
    [int]$OnlineMaxVersions,
    [ValidateRange(1, 128)]
    [int]$OnlineMaxCandidates,
    [ValidateRange(1, 86400)]
    [int]$OnlineCampaignTimeoutSeconds,
    [ValidateRange(0, 100000)]
    [int]$StopOnVulnCount,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$runnerPath = Join-Path $scriptRoot "scripts\wordpress\run-wordpress-phuzz.ps1"
$pluginDir = Join-Path $scriptRoot "web\applications\wordpress\_plugins"

function Show-Usage {
    Write-Host @"
Online-linked PHUZZ runner

Usage:
  .\phuzz.ps1
  .\phuzz.ps1 -PluginSlug gamipress
  .\phuzz.ps1 -Mode online-linked -PluginSlug hookphuzz-online-discovery-fixture -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3
  .\phuzz.ps1 -PluginSlug gamipress -DryRun

Online-linked is the only workflow. Zend runtime discovery is always enabled.

Options:
  -PluginSlug <slug>               Local plugin ZIP slug; no matching manual config required.
  -ForcePlugins                    Re-download the default plugin ZIP.
  -WebTimeoutSeconds <seconds>     WordPress readiness wait. Default: 240.
  -SeedWaitSeconds <seconds>       Live coverage snapshot wait. Default: 45.
  -OnlineTimeoutSeconds <seconds>  Per-candidate budget. Default/max: 120.
  -OnlineMaxVersions <count>       Versions including v0. Default: 2.
  -OnlineMaxCandidates <count>     Candidates per campaign. Default: 32.
  -OnlineCampaignTimeoutSeconds    Total campaign budget. Default: 3600.
  -StopOnVulnCount <count>         Stop after this many findings; 0 keeps fuzzing.
  -UseZendDiscovery                Accepted for existing online-linked commands; always enabled.
  -NoFollowLogs                    Accepted for existing online-linked commands; campaigns are bounded.
  phuzz.env                        Runtime settings; CLI flags override file values.
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
            Sort-Object -Unique
    )
}

function Read-PluginSlug {
    $slugs = @(Get-LocalPluginSlugs)
    if ($slugs.Count -eq 0) {
        Write-Host "No local plugin ZIP found. Using default: show-all-comments-in-one-page"
        return "show-all-comments-in-one-page"
    }

    Write-Host ""
    Write-Host "Choose local WordPress plugin:"
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

$settingsReaderPath = Join-Path $scriptRoot "scripts\wordpress\read-phuzz-env.ps1"
if (-not (Test-Path -LiteralPath $settingsReaderPath -PathType Leaf)) {
    throw "Missing PHUZZ settings reader: $settingsReaderPath"
}
. $settingsReaderPath
$runtimeSettings = Resolve-PhuzzRuntimeSettings -Path (Join-Path $scriptRoot "phuzz.env") -BoundParameters $PSBoundParameters
$OnlineTimeoutSeconds = $runtimeSettings["OnlineTimeoutSeconds"]
$OnlineMaxVersions = $runtimeSettings["OnlineMaxVersions"]
$OnlineMaxCandidates = $runtimeSettings["OnlineMaxCandidates"]
$OnlineCampaignTimeoutSeconds = $runtimeSettings["OnlineCampaignTimeoutSeconds"]
$StopOnVulnCount = $runtimeSettings["StopOnVulnCount"]

$UseZendDiscovery = $true
$interactive = -not ($PSBoundParameters.ContainsKey("Mode") -or $PSBoundParameters.ContainsKey("PluginSlug") -or $DryRun)

if (-not $PSBoundParameters.ContainsKey("PluginSlug")) {
    if ($interactive) {
        $PluginSlug = Read-PluginSlug
    } else {
        $PluginSlug = "show-all-comments-in-one-page"
    }
}

if (-not (Test-Path -LiteralPath $runnerPath)) {
    throw "Missing WordPress PHUZZ runner: $runnerPath"
}

$runnerParams = [ordered]@{
    PluginSlug = $PluginSlug
    WebTimeoutSeconds = $WebTimeoutSeconds
    SeedWaitSeconds = $SeedWaitSeconds
    StopOnVulnCount = $StopOnVulnCount
}
if ($ForcePlugins) {
    $runnerParams["ForcePlugins"] = $true
}
if ($NoFollowLogs) {
    $runnerParams["NoFollowLogs"] = $true
}

$runnerParams["UseZendDiscovery"] = $true
$runnerParams["OnlineTimeoutSeconds"] = $OnlineTimeoutSeconds
$runnerParams["OnlineMaxVersions"] = $OnlineMaxVersions
$runnerParams["OnlineMaxCandidates"] = $OnlineMaxCandidates
$runnerParams["OnlineCampaignTimeoutSeconds"] = $OnlineCampaignTimeoutSeconds

Write-Host "Delegating to WordPress PHUZZ runner:"
Write-Host ("  " + (Format-Command -CommandPath $runnerPath -Parameters $runnerParams))

if ($DryRun) {
    exit 0
}

& $runnerPath @runnerParams
if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
