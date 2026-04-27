# PHUZZ Hook Coverage Integration Plan

## Goal

- Ghep `Fuzz_WP` vao `phuzz-main` theo huong them adapter, han che sua source cu.
- Giu `phuzz-main` van chay voi line coverage hien tai.
- Them hook coverage bang UOPZ de WordPress target co the ghi request artifact song song.
- Them energy package cua hook coverage vao `phuzz-main`, nhung chi expose qua 1 ham bridge de ve sau co the tu noi vao scoring loop.

## Constraints

- Khong duoc lam vo fuzz loop hien tai cua `phuzz-main`.
- Khong thay doi cong thuc scoring mac dinh neu khong can thiet.
- UOPZ phai duoc load theo flow WordPress hook coverage da hoat dong o `Fuzz_WP`.
- Phai co file theo doi tien do va pham vi anh huong.

## Current Status

### Done

- Khao sat cau truc `phuzz-main` va `Fuzz_WP`.
- Doi chieu runtime line coverage hien tai cua `phuzz-main` voi runtime hook coverage cua `Fuzz_WP`.
- Re-check ngay `2026-04-26` sau khi `Fuzz_WP` duoc cap nhat lai.
- Xac nhan `phuzz-main/code/fuzzer/hook_energy/` hien dang mirror layout cu cua `Fuzz_WP/fuzzer-core/fuzzing/energy/`.
- Xac nhan `Fuzz_WP` hien tai da co layout moi tach rieng:
  - `Fuzz_WP/fuzzer-core/hook_energy/energy/`
  - `Fuzz_WP/fuzzer-core/hook_energy/seed/`
- Xac nhan bo PHP hook coverage cua `phuzz-main` da duoc doi ten va tach file so voi `Fuzz_WP`, nhung van cung vai tro runtime:
  - `auto_prepend.php` -> `hook_coverage/bootstrap/load_uopz_hook_coverage.php`
  - `uopz_hook.php` -> `hook_coverage/uopz_hook_wp.php` + `hook_coverage/instrumentation/uopz_hook_runtime.php`
- Chay GitNexus impact analysis cho cac diem chuan bi sua:
  - `DefaultScoringFormula`: risk `LOW`
  - `__fuzzer__get_coverage_report_and_save`: risk `LOW`
  - `__uopz_install_wp_hooks` ben `Fuzz_WP`: risk `LOW`

### In Progress

- Dong bo lai tai lieu de ten file va phan chia module khop voi `Fuzz_WP` moi.

### Next

- Khong co code change moi bat buoc duoc phat hien tu lan doi chieu nay.
- Neu muon `phuzz-main` giong layout moi cua `Fuzz_WP` 1:1, can lam mot dot refactor doi ten/tach package rieng.
- Chi khi muon dong bo layout moi thi moi can bo sung `seed/*` va doi package Python tu dang flat sang dang tach nhom.

## File Mapping After Re-check

### Python hook energy

- `phuzz-main/code/fuzzer/hook_energy/*.py`
  - Dang map voi layout cu:
    - `Fuzz_WP/fuzzer-core/fuzzing/energy/*.py`
  - Chua duoc doi sang layout moi:
    - `Fuzz_WP/fuzzer-core/hook_energy/energy/*.py`
    - `Fuzz_WP/fuzzer-core/hook_energy/seed/*.py`

- File phang hien co o `phuzz-main`:
  - `calculator.py`
  - `cli_watch.py`
  - `config.py`
  - `models.py`
  - `request_store.py`
  - `scheduler.py`
  - `state.py`
  - `__init__.py`

- File moi ben `Fuzz_WP` nhung chua co ben `phuzz-main`:
  - `fuzzer-core/hook_energy/energy/__init__.py`
  - `fuzzer-core/hook_energy/energy/calculator.py`
  - `fuzzer-core/hook_energy/energy/cli.py`
  - `fuzzer-core/hook_energy/energy/collector.py`
  - `fuzzer-core/hook_energy/energy/models.py`
  - `fuzzer-core/hook_energy/energy/reporter.py`
  - `fuzzer-core/hook_energy/energy/state.py`
  - `fuzzer-core/hook_energy/seed/__init__.py`
  - `fuzzer-core/hook_energy/seed/cli.py`
  - `fuzzer-core/hook_energy/seed/models.py`
  - `fuzzer-core/hook_energy/seed/pipeline.py`
  - `fuzzer-core/hook_energy/tests/test_hook_energy.py`
  - `fuzzer-core/hook_energy/tests/test_seed_pipeline.py`

### PHP hook coverage

- `phuzz-main/code/web/instrumentation/hook_coverage/bootstrap/load_uopz_hook_coverage.php`
  - Tuong duong vai tro voi `Fuzz_WP/fuzzer-core/bootstrap/auto_prepend.php`

- `phuzz-main/code/web/instrumentation/hook_coverage/bootstrap/uopz_mu_plugin.php`
  - Tuong duong vai tro voi `Fuzz_WP/fuzzer-core/bootstrap/uopz_mu_plugin.php`

- `phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php`
  - La ban adapt/rut gon tu `Fuzz_WP/fuzzer-core/instrumentation/uopz_hook.php`

- `phuzz-main/code/web/instrumentation/hook_coverage/instrumentation/uopz_hook_runtime.php`
  - La file runtime tach rieng ma `Fuzz_WP` ban goc chua tach thanh file doc lap

### Actual code drift found

- `phuzz-main/code/fuzzer/hook_energy/scheduler.py`
  - Khac `Fuzz_WP/fuzzer-core/fuzzing/energy/scheduler.py` o default path:
    - `phuzz-main`: `/shared-tmpfs/hook-coverage/...`
    - `Fuzz_WP`: `/var/www/uopz/output/...`
  - Day la khac biet co chu dich theo runtime cua `phuzz-main`, khong phai thieu logic moi.

## Expected Impact

### Directly Affected

- `phuzz-main/code/fuzzer/scoring.py`
  - Them 1 ham bridge de tinh hook energy tu request artifact.
  - Khong doi default scoring formula hien tai neu khong duoc goi.

- `phuzz-main/code/web/instrumentation/__fuzzer__startcov.php`
  - Them loader co dieu kien cho UOPZ hook coverage.
  - Giu nguyen line coverage flow hien tai.

- `phuzz-main/code/docker-compose.yml`
  - Them env de bat UOPZ hook coverage cho WordPress runtime mac dinh.

### Indirectly Affected

- WordPress web container cua `phuzz-main`
  - Se co them request artifact cho hook coverage neu `FUZZER_ENABLE_UOPZ=1`.

- Fuzzer Python side
  - Co them package hook energy va test, nhung fuzz loop cu van dung `DefaultScoringFormula` cho den khi nguoi dung tu noi them.

## Verification Plan

- Python:
  - `python -m unittest phuzz-main/code/fuzzer/tests/test_hook_energy_bridge.py`

- PHP syntax:
  - `php -l phuzz-main/code/web/instrumentation/__fuzzer__startcov.php`
  - `php -l phuzz-main/code/web/instrumentation/hook_coverage/bootstrap/load_uopz_hook_coverage.php`
  - `php -l phuzz-main/code/web/instrumentation/hook_coverage/bootstrap/uopz_mu_plugin.php`
  - `php -l phuzz-main/code/web/instrumentation/hook_coverage/instrumentation/uopz_hook_runtime.php`
  - `php -l phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php`

- Runtime/config sanity:
  - `docker compose -f phuzz-main/code/docker-compose.yml config`

## Verification Results

- So sanh lai filesystem va noi dung code giua `phuzz-main` va `Fuzz_WP` sau lan cap nhat moi:
  - `phuzz-main/code/fuzzer/hook_energy/*` so voi `Fuzz_WP/fuzzer-core/fuzzing/energy/*`
    - Giong nhau: `__init__.py`, `calculator.py`, `cli_watch.py`, `config.py`, `models.py`, `request_store.py`, `state.py`
    - Khac noi dung: `scheduler.py`
    - Khac biet duy nhat la default output path, khong co them logic moi
  - `phuzz-main/code/fuzzer/hook_energy/*` khong trung layout package moi `Fuzz_WP/fuzzer-core/hook_energy/{energy,seed,...}`
  - Bo PHP hook coverage cua `phuzz-main` da duoc rename/split, nen khong the so hash 1:1 voi file goc ben `Fuzz_WP`
  - Khong phat hien them code module moi bat buoc phai port vao `phuzz-main` chi vi `Fuzz_WP` duoc doi ten/tach package

- `python -m unittest phuzz-main/code/fuzzer/tests/test_hook_energy_bridge.py`
  - PASS
  - Xac nhan ham bridge moi tinh duoc hook energy va co the update hoac khong update state.

- `php -l` cho:
  - `phuzz-main/code/web/instrumentation/__fuzzer__startcov.php`
  - `phuzz-main/code/web/instrumentation/hook_coverage/bootstrap/load_uopz_hook_coverage.php`
  - `phuzz-main/code/web/instrumentation/hook_coverage/bootstrap/uopz_mu_plugin.php`
  - `phuzz-main/code/web/instrumentation/hook_coverage/instrumentation/uopz_hook_runtime.php`
  - `phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php`
  - Tat ca PASS.

- `docker compose -f phuzz-main/code/docker-compose.yml config`
  - PASS
  - Compose da nhan env moi `FUZZER_ENABLE_UOPZ=1` va `FUZZER_HOOK_OUTPUT_DIR=/shared-tmpfs/hook-coverage`.

- `docker compose up -d web --build --force-recreate`
  - PASS
  - Web container boot thanh cong voi image moi.

- Live request:
  - `Invoke-WebRequest http://127.0.0.1:8080/` tra ve `200`.
  - Trong container da co:
    - `/shared-tmpfs/hook-coverage/total_coverage.json`
    - `/shared-tmpfs/hook-coverage/requests/164801_GET_index_8b8b.json`
    - `/shared-tmpfs/hook-coverage/requests/164802_POST_wp-cron_php_b01b.json`
  - Xac nhan MU plugin da duoc sync vao `wp-content/mu-plugins/fuzzer-uopz-bootstrap.php`.
  - Xac nhan request artifact co schema `uopz-request-v3`, `executed_callback_ids`, `blindspot_callback_ids`, `new_hook_names`, `coverage_delta`, `score`, va `hook_coverage_summary`.

## Runtime Fixes Discovered During Verification

- Luc dau UOPZ runtime boot duoc nhung hook artifacts chua ghi ra file.
- Nguyen nhan that te la output dir moi `/shared-tmpfs/hook-coverage` chua duoc tao/chown trong `web/entrypoint.sh`.
- Da sua bang cach tao:
  - `/shared-tmpfs/hook-coverage`
  - `/shared-tmpfs/hook-coverage/requests`
  - va `chown -R www-data:www-data /shared-tmpfs/hook-coverage`

## Remaining Risks

- Hook energy da "dung duoc" qua package + bridge function, nhung chua duoc noi vao default fuzz scheduling loop cua `phuzz-main`.
- `phuzz-main` hien chua doi layout package sang dung naming moi cua `Fuzz_WP`; day la van de to chuc file/namespace, khong phai regression moi ve logic.
- Chua co test tu dong chay thang `EnergyScheduler` tren artifact that lay tu runtime Docker; hien moi verify schema/request artifact bang runtime va verify bridge bang unittest.
- Trong session nay khong co `gitnexus_detect_changes()` MCP tool, nen pham vi thay doi duoc doi chieu bang:
  - GitNexus impact analysis truoc khi sua
  - danh sach file da thay doi trong tai lieu nay
  - verification runtime/test sau khi sua

## Notes

- Sau khi doi chieu lai voi `Fuzz_WP` moi, ket luan hien tai la:
  - Can sua `Plan.md` de ten file va phan chia module dung voi thuc te moi
  - Khong co bang chung cho thay can them code moi vao `phuzz-main` ngay luc nay
  - Neu muon dong bo naming/layout 1:1 voi `Fuzz_WP`, do se la mot dot refactor rieng
- Hook energy duoc dua vao `phuzz-main` theo kieu package rieng + 1 ham bridge trong `scoring.py`.
- Flow mac dinh cua `phuzz-main` khong bi ep su dung hook energy ngay lap tuc.
- Muc tieu cua dot nay la "co the dung duoc", khong phai "da thay the scoring cu".
