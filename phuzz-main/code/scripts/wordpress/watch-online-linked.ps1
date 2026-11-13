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
$workersRoot = Join-Path $codeRoot "fuzzer\output\workers"

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

function Show-PriorityRounds($State, [string]$StatePath) {
    # A worker started by a new-param handoff keeps its priority round in
    # fuzzer/output/workers/priority/<worker_run_id>.json (name sanitized as in fuzzer.py _priority_log).
    $granted = @()
    $eventsPath = Join-Path (Split-Path -Parent $StatePath) "events.jsonl"
    if (Test-Path -LiteralPath $eventsPath -PathType Leaf) {
        $granted = @(Get-Content -LiteralPath $eventsPath -Encoding UTF8 | Where-Object { $_ -like '*"PRIORITY_SEED"*' } |
            ForEach-Object { try { $_ | ConvertFrom-Json } catch { } } |
            Where-Object { $_.status -eq "GRANTED" } | ForEach-Object { $_.version })
    }
    foreach ($version in @($State.versions | Where-Object { $_ })) {
        $name = ([string]$version.worker_run_id -replace '[^A-Za-z0-9_.-]+', '-').Trim('-')
        $round = $null
        if ($name) { $round = Read-JsonFile (Join-Path $workersRoot ("priority\{0}.json" -f $name)) }
        if (-not $round) {
            if ($granted -contains $version.version) { Write-Host ("Priority round {0}: granted, worker result not saved yet" -f $version.version) }
            continue
        }
        if ($round.status -ne "DONE") {
            Write-Host ("Priority round {0}: {1} {2} {3}" -f $version.version, $round.status, $round.reason, $round.detail)
            continue
        }
        $perField = @($round.per_field.PSObject.Properties | ForEach-Object { "{0}={1}" -f $_.Name, $_.Value }) -join ", "
        Write-Host ("Priority round {0}: mode={1}  seed_energy={2} ({3})  bonus={4}  granted={5}  attempted={6}" -f
            $version.version, $round.mode, $round.seed_energy, $round.seed_energy_source, $round.bonus, $round.granted, $round.attempted)
        Write-Host ("    per_field: {0}" -f $perField)
    }
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

    # Parallel phase (ONLINE_PARALLEL=1): the deadline is the coordinator's monotonic clock,
    # so the time left comes from budget.remaining_seconds at the last save.
    $parallel = @($state.versions | Where-Object { $_ -and $_.parallel -and -not $_.parallel.ended_at }) | Select-Object -Last 1
    if ($parallel) {
        $live = @($parallel.parallel.nodes | Where-Object { $_.started -and -not $_.stop_reason -and $null -eq $_.exit_code }).Count
        $left = "?"
        if ($state.budget -and $null -ne $state.budget.remaining_seconds -and $state.budget.saved_at) {
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
            $left = [Math]::Max(0, [int]($state.budget.remaining_seconds - ($now - $state.budget.saved_at)))
        }
        Write-Host ("Parallel: {0}/{1} nodes, {2}s left" -f $live, $parallel.parallel.requested_nodes, $left)
    }

    Show-PriorityRounds $state $active.state_path

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
        if ($_.kind -eq "PRIORITY_SEED" -and $_.status -eq "GRANTED") {
            # Priority round grant (core/online_handoff.py priority_energy); the worker logs the attempts it ran.
            $targets = @($_.targets | ForEach-Object { $_ -join ":" })
            $seed = if ($null -ne $_.seed_phuzz_energy) { $_.seed_phuzz_energy } else { "rescored by worker" }
            $grant = if ($_.mode -eq "carryover") {
                "max(1, {0} - {1}) = {2}" -f $_.allocated_energy, $_.attempts_used, [Math]::Max(1, $_.allocated_energy - $_.attempts_used)
            } else { "seed ({0}) + {1} new field(s)" -f $seed, $targets.Count }
            Write-Host ("      mode={0}  allocated={1}  used={2}  seed_energy={3}" -f $_.mode, $_.allocated_energy, $_.attempts_used, $seed)
            Write-Host ("      targets={0}  grant={1}" -f ($targets -join ","), $grant)
        }
    }
}

while ($true) {
    $runDirectory = Get-RunDirectory
    if (-not $Once) { Clear-Host }
    Show-Campaign $runDirectory
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
