# File Provider generated-seed proof run

Temporary guide for proving File Provider CVE-2025-4578 can be fuzzed from a generated hook seed while the hand-written PHUZZ config is empty.

Delete this file after you finish the test:

```powershell
Remove-Item -LiteralPath .\docs\guides\file-provider-generated-seed-proof.md
```

All commands below run from:

```powershell
cd phuzz-main\code
```

## Success criteria

- `fuzzer\configs\wordpress\file_provider_sqli.json` is `{}`.
- WordPress installs and activates `file-provider`.
- Hook seed generation emits `wp_ajax_nopriv_dfp_download_file`.
- The generated seed includes fuzzable query parameter `fileId`.
- The fuzzer runs with `FUZZER_CONFIG=../output/<run>/configs/dfp_download_file_generated_seed`, not `wordpress/file_provider_sqli`.
- `vulnerable-candidates.json` reports `SQLi`.

## 1. Confirm the hand config is empty

```powershell
Get-Content .\fuzzer\configs\wordpress\file_provider_sqli.json
```

Expected:

```json
{}
```

## 2. Ensure the vulnerable plugin ZIP exists

```powershell
New-Item -ItemType Directory -Force -Path .\web\applications\wordpress\_plugins | Out-Null
if (-not (Test-Path .\web\applications\wordpress\_plugins\file-provider.zip)) {
    Invoke-WebRequest `
        -Uri https://downloads.wordpress.org/plugin/file-provider.1.2.3.zip `
        -OutFile .\web\applications\wordpress\_plugins\file-provider.zip
}
```

## 3. Bootstrap WordPress with File Provider only

```powershell
$bootstrapOverride = Join-Path $env:TEMP "phuzz-file-provider-bootstrap.override.yml"
@(
    "services:",
    "  web:",
    "    environment:",
    "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/file-provider/",
    "      WP_TARGET_PLUGIN: file-provider"
) | Set-Content -LiteralPath $bootstrapOverride -Encoding ASCII

docker compose -f docker-compose.yml -f $bootstrapOverride down --volumes --remove-orphans
docker compose -f docker-compose.yml -f $bootstrapOverride up -d db web --build --force-recreate
```

Wait until WordPress responds:

```powershell
$deadline = (Get-Date).AddSeconds(240)
do {
    try {
        $ok = (Invoke-WebRequest -Uri "http://localhost:8080/" -UseBasicParsing -TimeoutSec 10).StatusCode -eq 200
    } catch {
        $ok = $false
    }
    if (-not $ok) { Start-Sleep -Seconds 5 }
} while (-not $ok -and (Get-Date) -lt $deadline)
if (-not $ok) { throw "WordPress did not become ready." }
```

Verify the plugin and endpoint:

```powershell
docker compose -f docker-compose.yml -f $bootstrapOverride exec -T web sh -lc "cd /var/www/html && ./wp-cli.phar core is-installed --allow-root && ./wp-cli.phar plugin list --allow-root --status=active --field=name"
Invoke-WebRequest -Uri "http://localhost:8080/wp-admin/admin-ajax.php?action=dfp_download_file&fileId=1" -UseBasicParsing -TimeoutSec 20 | Select-Object StatusCode,Content
```

## 4. Create a fresh run directory and collect coverage

```powershell
$runName = "file-provider-generated-seed-proof-$(Get-Date -Format yyyyMMdd-HHmmss)"
$run = Join-Path (Resolve-Path .\fuzzer\output) $runName
New-Item -ItemType Directory -Force -Path $run, "$run\source" | Out-Null

Invoke-WebRequest -Uri "http://localhost:8080/wp-admin/admin-ajax.php?action=dfp_download_file&fileId=1" -UseBasicParsing -TimeoutSec 20 | Out-Null
docker cp code-web-1:/shared-tmpfs/hook-coverage/total_coverage.json "$run\total_coverage.json"
Expand-Archive -LiteralPath .\web\applications\wordpress\_plugins\file-provider.zip -DestinationPath "$run\source" -Force
```

## 5. Generate hook seeds from coverage

```powershell
Push-Location .\fuzzer
python -m hook_energy.seed_generation.export_cli `
    --coverage-file "$run\total_coverage.json" `
    --output-dir "$run\seed_generation" `
    --container-source-root "/var/www/html/wp-content/plugins/file-provider" `
    --host-source-root "$run\source\file-provider" `
    --source-root "$run\source\file-provider"
Pop-Location
```

Check the generated seed:

```powershell
$seedDoc = Get-Content "$run\seed_generation\suggested_seeds.json" -Raw | ConvertFrom-Json
$seedItem = $seedDoc.suggested_seeds | Where-Object { $_.hook_name -eq "wp_ajax_nopriv_dfp_download_file" } | Select-Object -First 1
$seedItem.seed | ConvertTo-Json -Depth 10
```

Expected important fields:

- `method`: `POST`
- `path`: `/wp-admin/admin-ajax.php`
- `body.action`: `dfp_download_file`
- `query_params.fileId`: `FUZZ`
- `fuzzable_params`: `fileId`

## 6. Convert the generated seed to a PHUZZ adapter config

PHUZZ currently loads config JSON files, not `suggested_seeds.json` directly. This adapter is generated from the seed and stored in the run output directory.

```powershell
$configDir = Join-Path $run "configs"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$seed = $seedItem.seed

$bodyData = @()
foreach ($prop in $seed.body.PSObject.Properties) {
    $bodyData += @{ name = $prop.Name; value = [string]$prop.Value }
}

$queryData = @()
foreach ($prop in $seed.query_params.PSObject.Properties) {
    $queryData += @{ name = $prop.Name; value = [string]$prop.Value }
}

$config = [ordered]@{
    target = "http://web$($seed.path)"
    methods = @($seed.method)
    print_timestamps = $true
}

if ($bodyData.Count -gt 0) {
    $config.body_params = @{
        data = $bodyData
        fixed = [string[]]@($seed.fixed_params)
        fuzz = [string[]]@()
        weight = 1
    }
}

if ($queryData.Count -gt 0) {
    $config.query_params = @{
        data = $queryData
        fixed = @()
        fuzz = [string[]]@($seed.fuzzable_params)
        weight = 1
    }
}

$adapterConfig = Join-Path $configDir "dfp_download_file_generated_seed.json"
$config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $adapterConfig -Encoding ASCII
Get-Content $adapterConfig
```

## 7. Run PHUZZ with the generated-seed adapter

```powershell
$relativeConfig = "../output/$runName/configs/dfp_download_file_generated_seed"
$fuzzOverride = Join-Path $run "compose.generated-seed.override.yml"
@(
    "services:",
    "  fuzzer-wordpress-plugin:",
    "    environment:",
    "      FUZZER_CONFIG: $relativeConfig",
    "  web:",
    "    environment:",
    "      FUZZER_COVERAGE_PATH: /var/www/html/wp-content/plugins/file-provider/",
    "      WP_TARGET_PLUGIN: file-provider"
) | Set-Content -LiteralPath $fuzzOverride -Encoding ASCII

docker compose exec -T web sh -lc "rm -rf /shared-tmpfs/hook-coverage/requests/* /shared-tmpfs/mysql-error-reports/* /shared-tmpfs/error-reports/* /shared-tmpfs/coverage-reports/*"
docker compose -f docker-compose.yml -f $fuzzOverride up -d fuzzer-wordpress-plugin --force-recreate
docker inspect code-fuzzer-wordpress-plugin-1 --format '{{range .Config.Env}}{{println .}}{{end}}' | Select-String FUZZER_CONFIG
Start-Sleep -Seconds 60
```

## 8. Copy artifacts and verify SQLi

```powershell
New-Item -ItemType Directory -Force -Path "$run\fuzzer-output", "$run\requests" | Out-Null
Copy-Item -Recurse -Force -Path .\fuzzer\output\fuzzer-1\* -Destination "$run\fuzzer-output" -ErrorAction SilentlyContinue
docker logs code-fuzzer-wordpress-plugin-1 | Set-Content -LiteralPath "$run\fuzzer.full.log" -Encoding UTF8
docker cp code-web-1:/shared-tmpfs/hook-coverage/requests/. "$run\requests" | Out-Null
docker cp code-web-1:/shared-tmpfs/hook-coverage/total_coverage.json "$run\total_coverage.json" | Out-Null
docker compose -f docker-compose.yml -f $fuzzOverride stop fuzzer-wordpress-plugin

Select-String -Path "$run\fuzzer.full.log" -Pattern "Found SQLi! in|SQLi:|\[req \d+\]" | Select-Object -First 20
Get-Content "$run\fuzzer-output\vulnerable-candidates.json" -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 6
```

If this worked, the first request lines should be `POST` requests that mutate `fileId` from `FUZZ`, not `GET` requests seeded with `1 AND SLEEP(5)`.

## 9. Cleanup after testing

Delete this temporary guide file:

```powershell
Remove-Item -LiteralPath .\docs\guides\file-provider-generated-seed-proof.md
```

Optional local cleanup:

```powershell
docker compose -f docker-compose.yml -f $bootstrapOverride down --volumes --remove-orphans
```
