$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$target = Join-Path $scriptRoot "scripts\wordpress\run-wordpress-plugin-matrix.ps1"

& $target @args
if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
