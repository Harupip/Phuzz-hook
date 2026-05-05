# PHUZZ Scoring Modes Mini Doc

## Da lam duoc gi

- `DefaultScoringFormula` trong `scoring.py` bay gio la bo chon mode scoring.
- Mac dinh mode moi la `2`, tuc `PHUZZ+hook`.
- Mode cu `1`, tuc `PHUZZ`, van con de anh tat hook bonus khi can doi chieu.
- Hook energy da duoc noi truc tiep vao `calculate_priority(...)` va `calculate_energy(...)`.
- `calculate_score(...)` van giu cong thuc PHUZZ goc de de so sanh voi score path-based.
- Doan `DefaultScoringFormula` goc da duoc giu lai duoi dang comment ngay trong `scoring.py` de doi chieu.

## Agent note

- Truoc khi sua tiep `phuzz-main/code/fuzzer/scoring.py`, doc file nay truoc.
- Khi can doi mode, uu tien sua `ACTIVE_SCORING_MODE` trong `scoring.py`, khong doi flow sang file khac neu chua can.
- Neu sua cong thuc bonus hook hoac selector mode, cap nhat cung luc:
  - `phuzz-main/code/fuzzer/scoring.py`
  - `phuzz-main/code/fuzzer/tests/test_scoring_modes.py`
  - file mini doc nay
- Giữ logic PHUZZ goc de doi chieu. Neu can refactor, khong xoa block comment cua scoring cu khi chua co ban doi chieu ro rang.

## Da sua o dau

- Modify: `phuzz-main/code/fuzzer/scoring.py`
  - Them hang so:
    - `SCORING_MODE_PHUZZ = 1`
    - `SCORING_MODE_PHUZZ_HOOK = 2`
    - `ACTIVE_SCORING_MODE = 2`
  - Them `PhuzzScoringFormula`
  - Them `PhuzzHookScoringFormula`
  - `DefaultScoringFormula` chon mode theo hang so
- Add: `phuzz-main/code/fuzzer/tests/test_scoring_modes.py`
  - Test mode mac dinh
  - Test mode `1`
  - Test mode `2`

## Hanh vi moi

### Mode `1` = `PHUZZ`

- Dung cong thuc goc:
  - `score = hit_counter + len(paths)`
  - `priority = score`
  - `energy = max(1, parent.number_of_new_paths + abs(parent.score - candidate.score))`
- Khong cong hook bonus
- `candidate.hook_energy` va `candidate.hook_energy_avg` giu `0.0`

### Mode `2` = `PHUZZ+hook`

- `score` van la score PHUZZ goc
- `priority` duoc cong them hook bonus
- `energy` duoc cong them hook bonus
- `candidate` se duoc cap nhat them:
  - `base_score`
  - `base_priority`
  - `base_energy`
  - `final_energy`
  - `hook_request_id`
  - `hook_energy`
  - `hook_energy_avg`

## Cach doi mode

Chinh truc tiep trong `phuzz-main/code/fuzzer/scoring.py`:

```python
SCORING_MODE_PHUZZ = 1
SCORING_MODE_PHUZZ_HOOK = 2
ACTIVE_SCORING_MODE = SCORING_MODE_PHUZZ_HOOK
```

Neu muon quay ve PHUZZ goc:

```python
ACTIVE_SCORING_MODE = SCORING_MODE_PHUZZ
```

Neu muon bat lai PHUZZ+hook:

```python
ACTIVE_SCORING_MODE = SCORING_MODE_PHUZZ_HOOK
```

## Bien moi truong lien quan

- `FUZZER_HOOK_REQUESTS_DIR`
  - mac dinh: `/shared-tmpfs/hook-coverage/requests`
- `FUZZER_HOOK_PRIORITY_WEIGHT`
  - mac dinh: `1.0`
- `FUZZER_HOOK_ENERGY_WEIGHT`
  - mac dinh: `1.0`

## Ghi chu quan trong

- Toi khong sua `fuzzer.py` de doi flow chinh.
- Viec noi hook bonus duoc lam ngay trong `scoring.py` nhu anh yeu cau.
- `hook_energy` van doc tu request artifact `hook_coverage` thong qua `coverage_id` cua candidate.
- Cang mot callback bi execute nhieu lan truoc do, hook bonus cang giam theo cong thuc `1 / (N + 1)`.
- Viec chon `PHUZZ` hay `PHUZZ+hook` bay gio khong di qua env nua, ma xem ngay duoc trong `scoring.py`.

## Test da chay

```text
python -m unittest phuzz-main\code\fuzzer\tests\test_hook_energy_bridge.py phuzz-main\code\fuzzer\tests\test_hook_energy_integration.py phuzz-main\code\fuzzer\tests\test_scoring_modes.py
```

Ket qua:

```text
Ran 9 tests in 0.016s
OK
```
