$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$fuzzerOutputDir = Join-Path $root 'phuzz-main\code\fuzzer\output\fuzzer-1'
$exceptionsPath = Join-Path $fuzzerOutputDir 'exceptions-and-errors.json'
$vulnsPath = Join-Path $fuzzerOutputDir 'vulnerable-candidates.json'
$composeDir = Join-Path $root 'phuzz-main\code'

if (-not (Test-Path $fuzzerOutputDir)) {
    Write-Host "Khong tim thay output PHUZZ: $fuzzerOutputDir"
    Read-Host "Nhan Enter de dong"
    exit 1
}

function Get-CandidatesFromArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    if (-not (Test-Path $Path)) {
        return @()
    }

    $raw = Get-Content -Path $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @()
    }

    $json = $raw | ConvertFrom-Json
    $items = @()

    if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) {
        foreach ($candidate in $json) {
            $candidate | Add-Member -NotePropertyName debug_source -NotePropertyValue $Source -Force
            $items += $candidate
        }
        return $items
    }

    foreach ($prop in $json.PSObject.Properties) {
        foreach ($candidate in $prop.Value) {
            $candidate | Add-Member -NotePropertyName debug_source -NotePropertyValue "${Source}:$($prop.Name)" -Force
            $items += $candidate
        }
    }
    return $items
}

$allCandidates = @()
$allCandidates += Get-CandidatesFromArtifact -Path $vulnsPath -Source 'vulnerable-candidates'
$allCandidates += Get-CandidatesFromArtifact -Path $exceptionsPath -Source 'exceptions-and-errors'

if ($allCandidates.Count -eq 0) {
    Write-Host "Chua co candidate nao trong artifact."
    Write-Host "Thu chay lai PHUZZ truoc, roi mo file nay."
    Read-Host "Nhan Enter de dong"
    exit 1
}

$latestCandidate = $allCandidates |
    Sort-Object -Property @{ Expression = { [int64](($_.coverage_id -split '-')[0]) } }, @{ Expression = { $_.coverage_id } } -Descending |
    Select-Object -First 1

Write-Host "=== live candidate from PHUZZ ==="
Write-Host "source              =" $latestCandidate.debug_source
Write-Host "coverage_id         =" $latestCandidate.coverage_id
Write-Host "target              =" $latestCandidate.http_method $latestCandidate.http_target
Write-Host "mutated_param_type  =" $latestCandidate.mutated_param_type
Write-Host "mutated_param_name  =" $latestCandidate.mutated_param_name

$mutatedValue = $null
if ($latestCandidate.fuzz_params -and $latestCandidate.mutated_param_type) {
    $paramBucket = $latestCandidate.fuzz_params.PSObject.Properties[$latestCandidate.mutated_param_type]
    if ($paramBucket -and $paramBucket.Value) {
        $mutatedValue = $paramBucket.Value.PSObject.Properties[$latestCandidate.mutated_param_name].Value
    }
}
Write-Host "mutated_value       =" $mutatedValue
Write-Host ""

Write-Host "=== score ==="
Write-Host "score               =" $latestCandidate.score
Write-Host "base_score          =" $latestCandidate.base_score
Write-Host "priority            =" $latestCandidate.priority
Write-Host "base_priority       =" $latestCandidate.base_priority
Write-Host "base_energy         =" $latestCandidate.base_energy
Write-Host "final_energy        =" $latestCandidate.final_energy
Write-Host "hook_energy         =" $latestCandidate.hook_energy
Write-Host "hook_energy_avg     =" $latestCandidate.hook_energy_avg
Write-Host "number_of_new_paths =" $latestCandidate.number_of_new_paths
Write-Host ""

Write-Host "=== new_paths ==="
if ($latestCandidate.new_paths) {
    foreach ($path in $latestCandidate.new_paths) {
        Write-Host $path
    }
} else {
    Write-Host "(khong co new_paths)"
}
Write-Host ""

Write-Host "=== errors ==="
if ($latestCandidate.errors) {
    $latestCandidate.errors | ConvertTo-Json -Depth 6
} else {
    Write-Host "(khong co errors)"
}
Write-Host ""

Write-Host "=== vulns ==="
if ($latestCandidate.vulns) {
    $latestCandidate.vulns | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "(khong co vuln)"
}
Write-Host ""

Write-Host "=== response ==="
Write-Host "status              =" $latestCandidate.'response.status.code'
Write-Host "response_time_ms    =" $latestCandidate.'response.time'
Write-Host "response_body_len   =" $latestCandidate.'response.body.length'
Write-Host ""

Write-Host "=== latest web logs ==="
try {
    Push-Location $composeDir
    docker compose logs web --tail 8
    Pop-Location
} catch {
    if (Get-Location | Select-Object -ExpandProperty Path | ForEach-Object { $_ -ne $root }) {
        Set-Location $root
    }
    Write-Host "Khong lay duoc docker logs web."
    Write-Host $_.Exception.Message
}

Write-Host ""
Read-Host "Nhan Enter de dong"
