# Benchmark WordPress PHUZZ

## Long-run update

Benchmark nay khong con xem `30 phut` la cua so ket luan chinh. `20-30 phut`
chi nen dung de smoke/discovery: Docker da on dinh, request artifacts duoc ghi,
summary co EPS, va hook registry co du lieu. De danh gia fuzzing campaign, dung
`4-6 gio` cho pilot va `12-24 gio` cho moi target khi can bang chung paper-quality.

Runner hien co bon mode:

- `PHUZZ_RAW`: PHUZZ goc, `PHUZZ_SCORING_MODE=1`, `FUZZER_ENABLE_UOPZ=0`.
- `PHUZZ_TRACE`: PHUZZ goc nhung bat UOPZ de do coverage curve, `PHUZZ_SCORING_MODE=1`.
- `HOOK_TRACE`: Hook-aware scoring va UOPZ bat full-time, `PHUZZ_SCORING_MODE=2`.
- `HOOK_FAST`: trace bang UOPZ trong `-TraceMinutes`, export seed, sau do tat UOPZ va fuzz nhanh bang `FUZZER_CONFIG_FILE`.

Ly do tach `PHUZZ_RAW` va `PHUZZ_TRACE`: neu PHUZZ baseline van bat UOPZ thi ta chi
do algorithm trong moi truong cham, chua do toc do PHUZZ goc. EPS phai doc theo
mode:

- `PHUZZ_RAW` la moc toc do brute-force that.
- `PHUZZ_TRACE / HOOK_TRACE` cho overhead cua UOPZ.
- `HOOK_FAST` cho chien thuat hai pha `Tracing -> Fast Fuzzing`.

Moi run ghi them:

- `run_manifest.json`
- `coverage_timeline.json`
- `coverage_timeline.csv`
- `benchmark_summary.json`

`benchmark_summary.json` giu alias cu `unique_vulns_found_after_30min`, nhung metric
chinh moi la `unique_vulns_found_within_budget`.

Tai lieu nay mo ta benchmark moi de so sanh:

- `PHUZZ_RAW` -> baseline PHUZZ, khong UOPZ
- `PHUZZ_TRACE` -> baseline PHUZZ, co UOPZ de do hook coverage
- `HOOK_TRACE` -> PHUZZ + hook coverage
- `HOOK_FAST` -> trace ngan, seed export, roi fuzz nhanh khong UOPZ

Scope hien tai:

- Chay benchmark theo plugin WordPress bang override Compose tam thoi
- Runner tu dong chay ca `PHUZZ` va `HOOK`
- Moi mode mac dinh `5 runs`
- Lenh mac dinh benchmark `5` plugin dai dien:
  - `photo-gallery`
  - `crm-perks-forms`
  - `seo-local-rank`
  - `totop-link`
  - `webp-converter-for-media`

## 1. Muc tieu benchmark

Muc tieu chinh khong phai la noi "hook coverage tang bao nhieu", ma la do xem mode hook-aware co tim duoc loi nhanh hon khong.

Chi so chinh:

- `time_to_first_unique_vuln_seconds`
- `requests_to_first_unique_vuln`
- `time_to_3_unique_vulns_seconds`
- `requests_to_3_unique_vulns`
- `unique_vulns_found_within_budget`
- `requests_per_unique_vuln`
- `requests_per_second`
- `requests_per_minute`

Chi so phu:

- `unique_executed_callbacks`
- `blindspots_reduced`
- `hook_signal_request_ratio`
- `uopz_overhead_ratio` trong aggregate JSON khi co `PHUZZ_RAW`

Ket qua tong hop giua nhieu run dung `median`, khong dung average don thuan, vi fuzzing rat nhieu noise.

## 2. File moi va vai tro cua tung file

### `benchmark-wordpress-phuzz.ps1`

Day la host-side runner de chay benchmark.

No lam cac viec sau cho tung run:

1. Dat `PHUZZ_SCORING_MODE` trong `fuzzer/scoring.env`
2. Tao Compose override tam thoi theo plugin
3. `docker compose down --volumes --remove-orphans`
4. Xoa `fuzzer/output/fuzzer-1`
5. Start lai `db` va `web`
6. Doi `http://localhost:8080/` tra `200`
7. Verify plugin active, `WP_TARGET_PLUGIN`, `FUZZER_COVERAGE_PATH`
8. Start fuzzer service va verify `FUZZER_CONFIG`
9. Doi request fuzz dau tien xuat hien trong `/shared-tmpfs/hook-coverage/requests`
10. Bat dau cua so do benchmark
11. Sau khi het thoi gian, copy artifact ve local
12. Goi Python summarizer de tinh metric cho run do
13. Sau khi xong tat ca runs cua tung plugin, gom batch summary JSON/CSV

Luu y:

- Thoi gian bootstrap Docker/WordPress khong duoc tinh vao `30 phut`
- Cua so benchmark bat dau sau khi co request fuzz dau tien
- Script co restore lai noi dung goc cua `fuzzer/scoring.env` trong `finally`

### `fuzzer/benchmarking/summary.py`

Day la Python summarizer cho artifact benchmark.

No co 2 mode CLI:

```powershell
python .\fuzzer\benchmarking\summary.py summarize-run ...
python .\fuzzer\benchmarking\summary.py summarize-batch ...
```

Chuc nang chinh:

- Doc request artifacts tu `requests/*.json`
- Map `coverage_id` <-> request thong qua header `X-FUZZER-COVID`
- Doc `fuzzer-output/vulnerable-candidates.json`
- Dedupe vuln
- Tinh metric cho tung run
- Gom median theo mode
- Xuat `benchmark_results.json` va `benchmark_results.csv`

### `fuzzer/tests/test_benchmark_summary.py`

Test cho logic benchmark moi:

- dedupe unique vuln
- tinh `time_to_first_unique_vuln_seconds`
- tinh `time_to_3_unique_vulns_seconds`
- tinh `requests_per_unique_vuln`
- aggregate median giua nhieu run

## 3. Dedupe dang duoc tinh nhu the nao

Hien tai dedupe dung chu ky:

- `vuln type`
- `endpoint`
- `mutated param`
- `file/line` (uu tien `errors`, roi `exceptions`, roi fallback sang `paths`)

Noi ngan gon:

- cung loai loi
- cung endpoint
- cung param bi mutate
- cung vi tri loi

=> tinh la `1 unique vulnerability`

Vi du tuong duong:

- `WebFuzzXSSVulnCheck`
- `GET /wp-admin/admin-ajax.php?action=sac_post_type_call`
- `query_params:post_type`
- `bt-comments.php:569`

Neu lap lai nhieu candidate cung chu ky nay, benchmark chi tinh `1`.

## 4. Time benchmark duoc tinh nhu the nao

Script khong bat dau dem tu luc Docker khoi dong.

No dem nhu sau:

1. Start stack
2. Doi web ready
3. Start fuzzer
4. Doi file request dau tien xuat hien trong:

```text
/shared-tmpfs/hook-coverage/requests
```

5. Tu moc do moi bat dau cua so `30 phut`

Ly do:

- bootstrap Docker/DB/WordPress dao dong rat lon
- cai can so sanh la toc do fuzz tim loi, khong phai toc do boot moi truong

## 5. Metric duoc tinh tu artifact nao

### Request-level artifact

Tu web container:

```text
/shared-tmpfs/hook-coverage/requests/*.json
```

Dung de lay:

- thu tu request
- timestamp request
- mapping `coverage_id`
- executed callbacks

### Fuzzer output

Tu local:

```text
fuzzer/output/fuzzer-1/
```

Dung de lay:

- `vulnerable-candidates.json`
- candidate rows da bi vuln checker bat duoc

### Aggregate hook coverage

Tu web container:

```text
/shared-tmpfs/hook-coverage/total_coverage.json
```

Dung de lay:

- tong so callbacks da register
- blindspot callbacks con lai
- suy ra `blindspots_reduced`

## 6. Output benchmark nam o dau

Mac dinh output root:

```text
fuzzer/output/benchmarks/
```

Moi plugin benchmark se tao:

```text
fuzzer/output/benchmarks/<timestamp>-<plugin>/
```

Ben trong moi run:

```text
PHUZZ-run-01/
HOOK-run-01/
...
```

Moi run directory co:

- `requests/`
- `fuzzer-output/`
- `total_coverage.json` (neu co)
- `benchmark_summary.json`

Sau khi gom batch:

- `benchmark_results.json`
- `benchmark_results.csv`

## 7. Cach chay

Lenh mac dinh:

```powershell
.\benchmark-wordpress-phuzz.ps1
```

Lenh ro rang hon:

```powershell
.\benchmark-wordpress-phuzz.ps1 -RunsPerMode 1 -RunMinutes 10
```

Chi benchmark mot plugin:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery -RunsPerMode 1 -RunMinutes 10
```

Benchmark nhieu plugin cu the:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery,crm-perks-forms,seo-local-rank,totop-link,webp-converter-for-media -RunsPerMode 1 -RunMinutes 10
```

Sanity long-run mode:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery,crm-perks-forms -RunsPerMode 1 -RunMinutes 10 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE
```

Pilot 6 gio:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins crm-perks-forms,photo-gallery -RunsPerMode 1 -RunHours 6 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE,HOOK_FAST -TraceMinutes 20 -FastSeedLimit 5
```

Neu muon compose down sau khi chay xong:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery -RunsPerMode 1 -RunMinutes 10 -TearDownAfterBenchmark
```

## 8. Script nay hien tai support gi

Hien tai script support cac plugin benchmark:

```text
show-all-comments-in-one-page
photo-gallery
crm-perks-forms
seo-local-rank
totop-link
webp-converter-for-media
```

Runner khong sua tay `docker-compose.yml`.

No tao file override tam thoi de doi:

- `web.environment.WP_TARGET_PLUGIN`
- `web.environment.FUZZER_COVERAGE_PATH`
- `fuzzer-wordpress-plugin.environment.FUZZER_CONFIG`

Neu muon mo rong them plugin, can them it nhat:

- plugin metadata trong `scripts/benchmarks/benchmark-wordpress-phuzz.ps1`
- verify plugin da smoke-pass tren matrix truoc khi benchmark dai

## 9. Cac thay doi toi da them trong benchmark pass nay

Nhung thay doi moi phuc vu benchmark:

- them `scripts/benchmarks/benchmark-wordpress-phuzz.ps1`
- them package `fuzzer/benchmarking/`
- them `fuzzer/tests/test_benchmark_summary.py`
- them docs nay

Nhung file nay khong phai thay doi benchmark cua toi, nhung runner co doc/dua vao:

- `fuzzer/scoring.env`
- `docker-compose.yml`
- `fuzzer/scoring.py`
- `web` hook coverage request artifacts

## 10. Nhung gi benchmark nay chua lam

Benchmark nay chua:

- tu dong phan loai false positive / instrumentation noise nang hon schema dedupe hien tai
- tu dong freeze seed corpus hay request budget theo `N request`
- tu dong xuat bang markdown bao cao cuoi cung

No hien tai tap trung vao:

- mot nhom plugin dai dien
- 2 modes
- so phut benchmark do nguoi chay chon, vi du `10 phut / mode / plugin`
- artifact ro rang cho tung run
- dedupe on dinh de so sanh giua baseline va hook-aware
- median aggregation de giam noise

## 11. Lenh verify da dung trong turn implement

Da verify logic benchmark bang:

```powershell
python -m unittest fuzzer.tests.test_scoring_modes fuzzer.tests.test_benchmark_summary -v
```

Da verify PowerShell script parse OK truoc khi ket luan implementation xong.

## 12. Cach doc ket qua nhanh

Mo file:

```text
fuzzer/output/benchmarks/<timestamp>-<plugin>/benchmark_results.csv
```

Bang nay se co dang:

- `plugin`
- `mode`
- `run`
- `total_requests`
- `requests_per_second`
- `requests_per_minute`
- `time_to_first_unique_vuln_seconds`
- `requests_to_first_unique_vuln`
- `time_to_3_unique_vulns_seconds`
- `requests_to_3_unique_vulns`
- `unique_vulns_found_within_budget`
- `unique_vulns_found_after_30min` (compat alias)
- `requests_per_unique_vuln`
- `unique_executed_callbacks`
- `blindspots_reduced`
- `notes`

Neu median cua `HOOK` nho hon `PHUZZ` o:

- `time_to_first_unique_vuln_seconds`
- `requests_to_first_unique_vuln`

va dong thoi `unique_vulns_found_after_30min` cao hon,

thi do la bang chung thuc dung hon cho nhan dinh:

```text
hook-aware mode tim vuln nhanh hon baseline PHUZZ
```
