[CmdletBinding()]
param(
    [string]$RunId,
    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 5,
    [ValidateRange(0, 1000)]
    [int]$EventCount = 15,
    [switch]$Once
)

# Read-only view of a running online-linked campaign: versions of the active
# candidate (v0 -> vN) and its latest events. Re-resolves the active candidate
# on every refresh, so it follows the batch from one candidate to the next.
#
# Usage (from phuzz-main/code, in a second terminal while phuzz.ps1 runs;
# Windows PowerShell 5.1 is enough):
#   .\scripts\wordpress\watch-online-linked.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\wordpress\watch-online-linked.ps1
#   .\scripts\wordpress\watch-online-linked.ps1 -RunId <run-id> -Once
# Guide: docs/guides/run-wordpress-plugins.md (watch section).

$ErrorActionPreference = "Stop"
$codeRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$outputRoot = Join-Path $codeRoot "fuzzer\output\online-linked"

function Read-JsonFile([string]$Path) {
    # The coordinator may be rewriting the file; a failed read is retried next refresh.
    try { return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
}

function Get-RunDirectory {
    if ($RunId) {
        $path = Join-Path $outputRoot $RunId
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Run folder not found: $path" }
        return Get-Item -LiteralPath $path
    }
    $latest = Get-ChildItem -LiteralPath $outputRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $latest) { throw "No online-linked run under $outputRoot" }
    return $latest
}

function Show-Campaign($RunDirectory) {
    Write-Host ("Run: {0}   ({1})" -f $RunDirectory.Name, (Get-Date -Format "HH:mm:ss"))
    $batch = Read-JsonFile (Join-Path $RunDirectory.FullName "batch-state.json")
    if (-not $batch) { Write-Host "batch-state.json not readable yet."; return }

    $candidates = @($batch.candidates)
    $pending = if ($batch.pending_candidates) { @($batch.pending_candidates).Count } else { 0 }
    Write-Host ("Campaign: {0}   candidates started: {1}   queued: {2}" -f $batch.campaign_status, $candidates.Count, $pending)

    $active = $candidates | Where-Object { $_.state_path } | Select-Object -Last 1
    if (-not $active) { Write-Host "No candidate started yet."; return }
    Write-Host ("Candidate #{0}: {1}   [{2}]" -f $active.index, $active.hook_name, $active.state_path)

    $state = Read-JsonFile $active.state_path
    if (-not $state) { Write-Host "state.json not readable yet."; return }
    Write-Host ("Candidate status: {0} {1}" -f $state.terminal_status, $state.terminal_reason)

    if (-not $state.versions) { Write-Host "No version yet." }
    @($state.versions | Where-Object { $_ }) | Select-Object version, parent_version, status, worker_status, terminal_reason,
        @{ Name = "params"; Expression = { (@($_.known_parameters) | ForEach-Object { $_.name }) -join "," } } |
        Format-Table -AutoSize | Out-Host

    if ($EventCount -eq 0) { return }
    $eventsPath = Join-Path (Split-Path -Parent $active.state_path) "events.jsonl"
    if (-not (Test-Path -LiteralPath $eventsPath -PathType Leaf)) { Write-Host "No events yet."; return }
    # RUNTIME_OBSERVATION/IGNORED dominates the log and hides version progress.
    $events = foreach ($line in Get-Content -LiteralPath $eventsPath -Encoding UTF8) {
        try { $line | ConvertFrom-Json } catch { }
    }
    Write-Host "Latest events:"
    $events | Where-Object { $_.kind -ne "RUNTIME_OBSERVATION" } | Select-Object -Last $EventCount | ForEach-Object {
        Write-Host ("  {0,-24} {1,-9} {2,-32} {3}" -f $_.kind, $_.status, $_.reason, $_.version)
    }
}

while ($true) {
    $runDirectory = Get-RunDirectory
    if (-not $Once) { Clear-Host }
    Show-Campaign $runDirectory
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
