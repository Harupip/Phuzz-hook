# Demo Hook Seed Input Signatures

This guide shows how to demo the feature on branch `codex/hook-seed-input-signatures`.

The feature is not just "PHUZZ sends requests". It shows:

```text
WordPress hook coverage
-> callback source mapping
-> request input extraction
-> suggested seed with fuzzable params
-> optional PHUZZ run using the generated seed
```

## 1. Prerequisites

Open Docker Desktop first and wait until the engine is running.

All commands below run from:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code
```

Check Docker:

```powershell
docker compose version
docker compose ps
```

If Docker reports pipe or access errors, restart Docker Desktop and run PowerShell again.

## 2. Start WordPress and PHUZZ

Run the default WordPress target:

```powershell
.\run-wordpress-phuzz.ps1 -NoFollowLogs
```

This starts:

```text
db
web
fuzzer-wordpress-plugin
```

Check services:

```powershell
docker compose ps
```

Open WordPress:

```text
http://localhost:8080/
```

Watch PHUZZ live mutations:

```powershell
docker compose logs -f fuzzer-wordpress-plugin
```

For the default plugin, log lines may look like:

```text
mutated=query_params.post_type
```

Stop following logs with `Ctrl+C`.

## 3. Export the New Hook-Aware Seed Demo

This is the important step for this branch. It maps plugin source from the ZIP so the exporter can scan callback code and discover fuzzable params.

Run:

```powershell
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$demoRoot = Join-Path (Get-Location) "fuzzer\output\seed-demo-$stamp"
$sourceRoot = Join-Path $demoRoot "source"
$seedRoot = Join-Path $demoRoot "seed_generation"
$coveragePath = Join-Path $demoRoot "total_coverage.json"

New-Item -ItemType Directory -Force -Path $sourceRoot, $seedRoot | Out-Null

Expand-Archive `
  -LiteralPath ".\web\applications\wordpress\_plugins\show-all-comments-in-one-page.zip" `
  -DestinationPath $sourceRoot `
  -Force

$web = (docker compose ps -q web).Trim()
docker cp "${web}:/shared-tmpfs/hook-coverage/total_coverage.json" $coveragePath

cd .\fuzzer

python -m hook_energy.seed_generation.export_cli `
  --coverage-file $coveragePath `
  --output-dir $seedRoot `
  --source-root $sourceRoot

cd ..

Write-Host "Demo output: $demoRoot"
```

Expected summary:

```text
Seed export summary: registered=<n> | uncovered=<n> | direct_http_candidates=<n>
```

## 4. View the Generated Seed

Find the latest demo folder:

```powershell
$latestDemo = Get-ChildItem .\fuzzer\output -Directory -Filter "seed-demo-*" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

$latestDemo.FullName
```

Open the readable seed report:

```powershell
Get-Content "$($latestDemo.FullName)\seed_generation\suggested_seeds.md"
```

Open the detailed JSON:

```powershell
Get-Content "$($latestDemo.FullName)\seed_generation\suggested_seeds.json"
```

For the default plugin, the important output should look like:

```text
Body: {"action": "sac_post_type_call", "post_type": "FUZZ", "post_category": "FUZZ", "post_id": "FUZZ"}
```

In JSON, check:

```json
"source_resolution": {
  "status": "zip_mapped"
}
```

and:

```json
"fuzzable_params": [
  "post_type",
  "post_category",
  "post_id"
]
```

If `source_resolution.status` is `unresolved`, the source ZIP mapping did not work. Re-run the export step with `--source-root`.

## 5. Show the Difference From the Old Output

Without source mapping, the seed usually only has:

```json
"body": {
  "action": "sac_post_type_call"
}
```

With this branch and `--source-root`, the seed includes fuzzable inputs:

```json
"body": {
  "action": "sac_post_type_call",
  "post_type": "FUZZ",
  "post_category": "FUZZ",
  "post_id": "FUZZ"
}
```

Demo line:

```text
Before, the seed generator could map the hook to admin-ajax action.
Now it also scans callback source and discovers request-controlled params.
```

## 6. Run the Full Generated-Seed Evaluation

Use this when you want to show that generated seeds are turned into PHUZZ configs and used in a real fuzzer run.

Fast demo run:

```powershell
.\scripts\evaluations\run-hookseed-evaluation.ps1 `
  -SkipDownload `
  -GamiPressSeconds 30 `
  -CscaSeconds 30
```

If required plugin ZIPs are missing and network is available, omit `-SkipDownload`:

```powershell
.\scripts\evaluations\run-hookseed-evaluation.ps1 `
  -GamiPressSeconds 30 `
  -CscaSeconds 30
```

While it runs, watch PHUZZ logs in another PowerShell:

```powershell
docker compose logs -f fuzzer-wordpress-plugin
```

Look for generated-seed params being mutated, such as:

```text
mutated=body.orderby
mutated=body.sid
mutated=query_params.cnt
```

## 7. View Evaluation Results

Find the latest evaluation folder:

```powershell
$latestEval = Get-ChildItem .\fuzzer\output\evaluations -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

$latestEval.FullName
```

Open the summary:

```powershell
Get-Content "$($latestEval.FullName)\evaluation-summary.md"
```

Key columns:

```text
Param auto
Callback reached
Requests
```

Good demo signs:

```text
Param auto = True
Callback reached = True
Requests > 0
```

Also inspect generated seeds and configs:

```powershell
Get-ChildItem "$($latestEval.FullName)" -Recurse -Filter suggested_seeds.json
Get-ChildItem "$($latestEval.FullName)\configs"
```

## 8. What to Say During Demo

Use this short explanation:

```text
HARgen starts from browser traffic that already happened.
This branch starts from WordPress hook coverage. It finds active uncovered hooks, maps direct HTTP hooks to admin-ajax/admin-post, maps container source paths to plugin source on the host, scans callback code for request inputs, and emits seeds with fuzzable params.
```

Then show:

```text
suggested_seeds.md
suggested_seeds.json
evaluation-summary.md
docker compose logs -f fuzzer-wordpress-plugin
```

## 9. Cleanup

Stop containers:

```powershell
docker compose down
```

Remove only demo seed folders if needed:

```powershell
Get-ChildItem .\fuzzer\output -Directory -Filter "seed-demo-*" |
  Remove-Item -Recurse -Force
```

Do not remove `fuzzer\output\fuzzer-1` if you still need current fuzzer artifacts.
