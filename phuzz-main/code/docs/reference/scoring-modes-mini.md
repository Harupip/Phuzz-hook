# PHUZZ Scoring Modes Mini Doc

## Da lam duoc gi

- `DefaultScoringFormula` trong `scoring.py` bay gio la bo chon mode scoring.
- Mac dinh mode moi la `2`, tuc `PHUZZ+hook`.
- Mode cu `1`, tuc `PHUZZ`, van con de anh tat hook feedback khi can doi chieu.
- Co the doi mode va tham so blend bang file `phuzz-main/code/fuzzer/scoring.env`.
- Hook energy da duoc noi truc tiep vao `calculate_priority(...)` va `calculate_energy(...)`.
- `priority` van cong additive theo hook signal, nhung `energy` da chuyen sang weighted blend giua PHUZZ base va hook energy.
- `calculate_score(...)` van giu cong thuc PHUZZ goc de de so sanh voi score path-based.
- Doan `DefaultScoringFormula` goc da duoc giu lai duoi dang comment ngay trong `scoring.py` de doi chieu.

## Agent note

- Truoc khi sua tiep `phuzz-main/code/fuzzer/scoring.py`, doc file nay truoc.
- Khi can doi mode luc chay, uu tien sua `phuzz-main/code/fuzzer/scoring.env`.
- Neu can doi default trong code, sua `ACTIVE_SCORING_MODE` trong `scoring.py`.
- Neu sua cong thuc hook feedback hoac selector mode, cap nhat cung luc:
  - `phuzz-main/code/fuzzer/scoring.py`
  - `phuzz-main/code/fuzzer/tests/test_scoring_modes.py`
  - `phuzz-main/code/fuzzer/scoring.env`
  - file mini doc nay
- Giữ logic PHUZZ goc de doi chieu. Neu can refactor, khong xoa block comment cua scoring cu khi chua co ban doi chieu ro rang.

## Da sua o dau

- Modify: `phuzz-main/code/fuzzer/scoring.py`
  - Them hang so:
    - `SCORING_MODE_PHUZZ = 1`
    - `SCORING_MODE_PHUZZ_HOOK = 2`
    - `ACTIVE_SCORING_MODE` doc tu `PHUZZ_SCORING_MODE`, mac dinh `2`
    - `DEFAULT_HOOK_REQUESTS_DIR` doc tu `FUZZER_HOOK_REQUESTS_DIR`
    - `DEFAULT_HOOK_PRIORITY_WEIGHT` doc tu `FUZZER_HOOK_PRIORITY_WEIGHT`
    - `DEFAULT_HOOK_ENERGY_BASE_WEIGHT` doc tu `FUZZER_HOOK_ENERGY_BASE_WEIGHT`
    - `DEFAULT_HOOK_ENERGY_WEIGHT` giu lai nhu alias fallback de tuong thich nguoc
    - `DEFAULT_HOOK_MIN_ENERGY_SCALE` doc tu `FUZZER_HOOK_MIN_ENERGY_SCALE`
  - Them `PhuzzScoringFormula`
  - Them `PhuzzHookScoringFormula`
  - `DefaultScoringFormula` chon mode theo hang so
- Add: `phuzz-main/code/fuzzer/scoring.env`
  - File env co comment de bat/tat mode, blend weight, va min hook scale khi chay fuzzer container
- Modify: `phuzz-main/code/docker-compose.yml`
  - Fuzzer service nap `./fuzzer/scoring.env` bang `env_file`
- Add: `phuzz-main/code/fuzzer/tests/test_scoring_modes.py`
  - Test mode mac dinh
  - Test mode `1`
  - Test mode `2`
  - Test env override cho mode, request dir, priority weight, energy base weight, min hook scale, va deprecated fallback alias

## Hanh vi moi

### Mode `1` = `PHUZZ`

- Dung cong thuc goc:
  - `score = hit_counter + len(paths)`
  - `priority = score`
  - `energy = max(1, parent.number_of_new_paths + abs(parent.score - candidate.score))`
- Khong co hook feedback
- `candidate.hook_energy` va `candidate.hook_energy_avg` giu `0.0`

### Mode `2` = `PHUZZ+hook`

- `score` van la score PHUZZ goc
- `priority` van cong additive theo `base_priority + hook_energy * weight`
- `energy` dung weighted blend:
  - `base = max(1, int(base_energy))`
  - `hook = clamp(hook_energy, 0.0, 1.0)`
  - `W = clamp(weight, 0.0, 1.0)`
  - `H = max(min_hook_scale, base)`
  - `final_energy = ceil((base * W) + (hook * (1 - W) * H))`
- Final energy van duoc floor ve it nhat `1` de scheduler co integer budget hop le
- `candidate` se duoc cap nhat them:
  - `base_score`
  - `base_priority`
  - `base_energy`
  - `final_energy`
  - `hook_request_id`
  - `hook_energy`
  - `hook_energy_avg`

## Cach doi mode bang env

Sua file `phuzz-main/code/fuzzer/scoring.env`:

```env
# 1 = PHUZZ goc
# 2 = PHUZZ + hook coverage feedback
PHUZZ_SCORING_MODE=2
```

## Benchmark mode moi

Benchmark runner khong sua truc tiep `scoring.env` nua. No inject env bang
Compose override cho tung mode:

- `PHUZZ_RAW`: `PHUZZ_SCORING_MODE=1`, `FUZZER_ENABLE_UOPZ=0`.
- `PHUZZ_TRACE`: `PHUZZ_SCORING_MODE=1`, `FUZZER_ENABLE_UOPZ=1`.
- `HOOK_TRACE`: `PHUZZ_SCORING_MODE=2`, `FUZZER_ENABLE_UOPZ=1`.
- `HOOK_FAST`: trace truoc bang `HOOK_TRACE`, export seed, sau do chay fast
  phase voi `PHUZZ_SCORING_MODE=1`, `FUZZER_ENABLE_UOPZ=0`, va
  `FUZZER_CONFIG_FILE=/app/output/.../hook-fast-config.json`.

Khac biet quan trong:

- `PHUZZ_RAW` moi la toc do PHUZZ goc khong co overhead UOPZ.
- `PHUZZ_TRACE` giu PHUZZ scoring nhung bat UOPZ de co hook coverage curve.
- `HOOK_TRACE` dung hook-aware scoring va bat UOPZ full-time.
- `HOOK_FAST` dung hook discovery nhu pha khoi dong, roi tat UOPZ de lay EPS cao hon.

Neu muon quay ve PHUZZ goc:

```env
PHUZZ_SCORING_MODE=1
```

Neu muon bat lai PHUZZ+hook:

```env
PHUZZ_SCORING_MODE=2
```

## Bien moi truong lien quan

- `PHUZZ_SCORING_MODE`
  - mac dinh: `2`
  - `1` = PHUZZ goc, `2` = PHUZZ+hook
- `FUZZER_HOOK_REQUESTS_DIR`
  - mac dinh: `/shared-tmpfs/hook-coverage/requests`
  - noi fuzzer doc request artifact hook coverage de ghep voi `candidate.coverage_id`
- `FUZZER_HOOK_PRIORITY_WEIGHT`
  - mac dinh: `1.0`
  - cong vao priority theo `base_priority + hook_energy * weight`
- `FUZZER_HOOK_ENERGY_BASE_WEIGHT`
  - mac dinh: `0.8`
  - phan trong so giu lai cho PHUZZ base energy trong weighted blend
- `FUZZER_HOOK_MIN_ENERGY_SCALE`
  - mac dinh: `4`
  - khi `base_energy` nho, phan hook side van scale toi thieu theo moc nay
- `FUZZER_HOOK_ENERGY_WEIGHT`
  - deprecated fallback alias
  - chi duoc doc khi `FUZZER_HOOK_ENERGY_BASE_WEIGHT` khong duoc set
- `PHUZZ_SCORE_DEBUG`
  - mac dinh: `0`
  - `1` de in log chi tiet khi `calculate_score()` dem path/line
- `FUZZER_CONFIG_FILE`
  - optional
  - neu set, fuzzer doc config JSON tu path nay thay vi `fuzzer/configs/<FUZZER_CONFIG>.json`
  - dung cho `HOOK_FAST` generated config
- `PHUZZ_WRITE_REQUEST_EVENTS`
  - mac dinh: `1`
  - ghi `fuzzer/output/fuzzer-<id>/request-events.jsonl` de tinh EPS ca khi UOPZ tat

## Ghi chu quan trong

- Toi khong sua `fuzzer.py` de doi flow chinh.
- Viec noi hook feedback duoc lam ngay trong `scoring.py` nhu anh yeu cau.
- `hook_energy` van doc tu request artifact `hook_coverage` thong qua `coverage_id` cua candidate.
- Cang mot callback bi execute nhieu lan truoc do, raw `hook_energy` cang giam theo cong thuc `1 / (N + 1)`.
- Scheduler van dung integer mutate budget, nen weighted blend se duoc `ceil(...)` o buoc cuoi cung.
- Neu `hook_energy` thap va `W < 1`, final energy co the thap hon baseline PHUZZ. Day la thay doi co chu dich cua cong thuc moi.
- Viec chon `PHUZZ` hay `PHUZZ+hook` bay gio di qua `scoring.env`, nhung constants `1` va `2` van nam ngay trong `scoring.py` de de audit.

## Test da chay

```text
python -m unittest phuzz-main\code\fuzzer\tests\test_hook_energy_bridge.py phuzz-main\code\fuzzer\tests\test_hook_energy_integration.py phuzz-main\code\fuzzer\tests\test_scoring_modes.py -v
```

Ket qua:

```text
Ran 12 tests in 0.029s
OK
```
