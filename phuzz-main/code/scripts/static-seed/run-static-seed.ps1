param(
    [Parameter(Mandatory = $true)]
    [string]$PluginPath,
    [Parameter(Mandatory = $true)]
    [string]$PluginSlug,
    [string]$OutputDir,
    [string]$BaseUrl = "http://web",
    [switch]$IncludeRest,
    [switch]$IncludeUnresolved,
    [switch]$RunAst,
    [switch]$NoWriteConfigs
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$scriptRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir "..\..")).Path
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Convert-ToContainerPath {
    param([string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $root = (Resolve-Path -LiteralPath $scriptRoot).Path
    if (-not $resolved.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path must be under $root so docker compose can mount it: $resolved"
    }

    $relative = $resolved.Substring($root.Length).TrimStart("\", "/")
    return "/workspace/code/" + ($relative -replace "\\", "/")
}

Push-Location $scriptRoot
try {
    $resolvedPluginPath = if ([System.IO.Path]::IsPathRooted($PluginPath)) {
        (Resolve-Path -LiteralPath $PluginPath).Path
    } else {
        (Resolve-Path -LiteralPath (Join-Path $scriptRoot $PluginPath)).Path
    }

    if (-not $OutputDir) {
        $OutputDir = Join-Path $scriptRoot (Join-Path "fuzzer\output\static-seed" "$timestamp-$PluginSlug")
    } elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
        $OutputDir = Join-Path $scriptRoot $OutputDir
    }
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $containerPluginPath = Convert-ToContainerPath -Path $resolvedPluginPath
    $containerOutputDir = Convert-ToContainerPath -Path $OutputDir

    $scanArgs = @(
        "run", "--rm", "static-seed",
        "scan",
        "--plugin-path", $containerPluginPath,
        "--plugin-slug", $PluginSlug,
        "--output-dir", $containerOutputDir,
        "--base-url", $BaseUrl
    )

    if ($IncludeRest) {
        $scanArgs += "--include-rest"
    }
    if ($IncludeUnresolved) {
        $scanArgs += "--include-unresolved"
    }
    if (-not $NoWriteConfigs) {
        $scanArgs += "--write-configs"
    }

    docker compose @scanArgs
    if ($LASTEXITCODE -ne 0) {
        throw "static-seed scan failed with exit code $LASTEXITCODE."
    }

    if ($RunAst) {
        $astOutputDir = "$containerOutputDir/ast"
        docker compose run --rm --entrypoint php static-seed /app/static_analysis/php_ast/scan.php --source $containerPluginPath --out $astOutputDir
        if ($LASTEXITCODE -ne 0) {
            throw "PHP AST scan failed with exit code $LASTEXITCODE."
        }
    }

    Write-Host "Static seed artifacts:"
    Write-Host "  $OutputDir"
} finally {
    Pop-Location
}
