[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$codeRoot = $PSScriptRoot
$settingsReaderPath = Join-Path $codeRoot "scripts\wordpress\read-phuzz-env.ps1"
. $settingsReaderPath

$settings = Read-PhuzzEnv -Path (Join-Path $codeRoot "phuzz.env")
$expectedValue = [string]$settings["CONFIG_COMPARE_EXPECTED"]
$actualValue = [string]$settings["CONFIG_COMPARE_ACTUAL"]
$policy = [string]$settings["CONFIG_COMPARE_POLICY"]
if ([string]::IsNullOrWhiteSpace($policy)) {
    $policy = "strict"
}
$policy = $policy.ToLowerInvariant()

if ([string]::IsNullOrWhiteSpace($expectedValue)) {
    throw "Set CONFIG_COMPARE_EXPECTED in phuzz.env."
}
if ([string]::IsNullOrWhiteSpace($actualValue)) {
    throw "Set CONFIG_COMPARE_ACTUAL in phuzz.env."
}
if ($policy -notin @("strict", "semantic")) {
    throw "CONFIG_COMPARE_POLICY must be strict or semantic."
}

function Resolve-CompareConfigPath {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)

    if ([System.IO.Path]::IsPathRooted($Value)) {
        $path = $Value
    } else {
        $path = Join-Path $codeRoot $Value
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$Name does not name a file: $path"
    }
    return (Resolve-Path -LiteralPath $path).Path
}

$expectedPath = Resolve-CompareConfigPath -Value $expectedValue -Name "CONFIG_COMPARE_EXPECTED"
$actualPath = Resolve-CompareConfigPath -Value $actualValue -Name "CONFIG_COMPARE_ACTUAL"
$fuzzerRoot = Join-Path $codeRoot "fuzzer"
$compareExitCode = 2

Push-Location $fuzzerRoot
try {
    & rtk proxy python -m config_comparison.cli `
        --expected $expectedPath `
        --actual $actualPath `
        --policy $policy `
        --format text
    $compareExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

exit $compareExitCode
