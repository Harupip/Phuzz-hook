# Zend REST ID Discovery Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Làm cho flow Zend bắt được tham số `id` của REST callback dùng ArrayAccess như `isset($request['id'])`, đồng thời bảo đảm callback thật sự đã được nạp vào target context trước khi coi bằng chứng là hợp lệ.

**Architecture:** Sửa theo chuỗi bằng chứng: nạp đủ callback registry → ghi đủ opcode events → nhận diện static ArrayAccess nhưng không tự đoán transport → chạy probe POST theo từng bucket → chỉ sau runtime evidence mới export `fuzzable_params`. UOPZ name-only evidence vẫn không được dùng để chứng minh POST body.

**Tech Stack:** C PHP opcode extension, Python seed-generation/Zend bridge, Python `unittest`, PowerShell/Docker WordPress runtime, LearnPress ZIP fixture.

**Spec:** `fuzzer/zend_discovery/AGENT_HANDOFF.md`, `fuzzer/zend_discovery/rest_runtime.py`, và artifacts điều tra tại `fuzzer/output/seed_generation/zend-bridge/learnpress-20260824T112855Z/`.

## Global Constraints

- Không hard-code `learnpress`, `finish_lesson`, hoặc tên callback cụ thể trong production code.
- Không biến schema, method, tên `get_param`, hay `isset($request['id'])` thành bằng chứng POST/JSON. Những nguồn này chỉ là candidate name.
- Chỉ `rest_parameter_events` có callback attribution, route identity, method, bucket/path hợp lệ mới được dùng để export fuzzable parameter.
- Nếu registry bị truncate, event buffer bị overflow, hoặc identity không khớp thì fail closed: giữ `replay_only`/blocked và ghi lý do.
- Probe có thể dùng giá trị typed sentinel để kích hoạt read; probe không tạo dữ liệu DB và không được coi application response `200` là business success.
- Giữ nguyên DB dùng chung và các thay đổi không liên quan, đặc biệt `research/` đang untracked.
- Phân biệt rõ các trạng thái: callback reached, parameter observed, parameter exported, fuzzing-ready, replay PASS, và application-level error.

---

## Task 1: Add failing regression tests for the three observed failures

**Files:**

- Modify `fuzzer/tests/test_seed_generation_input_extractor.py`.
- Modify `fuzzer/tests/test_zend_discovery.py`.
- Modify `fuzzer/tests/test_uopz_multistage_metadata_contract.py` only for artifact-contract assertions.

- [ ] Add an extractor test using a REST callback source containing both `isset($request['id'])` and `$request['id']`. Assert one `id` row with `source=REST_ARRAY_ACCESS`, `location=unknown`, and `confidence=static_rest_array_access` when the callback is marked as a REST route.
- [ ] Add a negative extractor test for a non-REST function that reads a local array such as `$values['id']`; assert that it is not reported as a REST request parameter.
- [ ] Add a Zend normalization test where `rest_parameter_events` contains the exact LearnPress canonical callback but `target_loading.loaded_callbacks` does not contain it; assert that normalization returns no parameter.
- [ ] Add the matching positive test with the canonical callback present in `loaded_callbacks`; assert that `id` becomes one fuzzable `form` parameter.
- [ ] Add a test proving duplicate registry registrations do not make a complete target load look partial, while rejected/overflow targets do.
- [ ] Add a test proving non-zero opcode event loss prevents final REST evidence from being exported.
- [ ] Add an artifact contract assertion for `target_loading.loaded_callbacks`, target capacity/overflow fields, and event-buffer capacity/loss fields.
- [ ] Run the focused tests and confirm the new tests fail for the current implementation: ArrayAccess is absent, target membership is not checked, and overflow is not represented distinctly.

**Checkpoint:** tests demonstrate each failure independently; no implementation change is mixed into this task.

---

## Task 2: Fix C target loading and event retention

**Files:**

- Modify `fuzzer/zend_discovery/extension/php_hookphuzz_opcode.h`.
- Modify `fuzzer/zend_discovery/extension/hookphuzz_opcode.c`.
- Modify the C-facing assertions in `fuzzer/tests/test_zend_discovery.py`.

- [ ] Replace the current 256-target behavior with a safe registry capacity that covers the current 376 unique LearnPress callbacks and leaves headroom; retain an explicit upper bound rather than allowing unbounded allocation.
- [ ] Change `hookphuzz_add_target` to return a distinct result for `added`, `duplicate`, `invalid`, and `capacity_exhausted`. Do not count capacity exhaustion as `duplicate_count`.
- [ ] Emit `target_capacity`, `capacity_exhausted_count`, `requested_target_count`, and the exact canonical `loaded_callbacks` list in `target_loading`.
- [ ] Define `load_status=loaded` when every valid unique callback was loaded, even if duplicate registrations exist. Use `partially_loaded` only when valid targets were rejected/overflowed or the registry contains invalid entries.
- [ ] Increase the opcode event capacity enough for the current LearnPress run and expose `event_capacity` together with existing `event_count` and `dropped_event_count`.
- [ ] Keep all existing callback-context attribution rules unchanged; the change is target loading/capacity observability, not a broadening to observe unrelated PHP functions.
- [ ] Rebuild the extension and run the C contract tests before touching Python gates.

**Expected result:** the LearnPress registry reports at least 376 loaded unique callbacks, `finish_lesson` is present in `loaded_callbacks`, `capacity_exhausted_count=0`, and the targeted request can finish without event loss.

**Checkpoint:** C artifact alone proves whether the callback is loaded; a `partially_loaded` status caused only by duplicates is no longer accepted as a substitute for exact membership.

---

## Task 3: Recognize REST ArrayAccess without inventing transport

**Files:**

- Modify `fuzzer/hook_energy/seed_generation/input_extractor.py`.
- Modify `fuzzer/hook_energy/seed_generation/common_generator.py`.
- Modify `fuzzer/zend_discovery/parameter_seeds.py`.
- Modify `fuzzer/hook_energy/seed_generation/pipeline.py`.
- Extend `fuzzer/tests/test_seed_generation_input_extractor.py` and relevant REST tests in `fuzzer/tests/test_zend_discovery.py`.

- [ ] Pass the resolved entrypoint type into static extraction before extraction runs, so the extractor knows whether the callback is a REST route without inspecting plugin names.
- [ ] For REST callbacks, identify formal callback argument variables from the function declaration/metadata and detect quoted ArrayAccess keys on those variables. Support whitespace and both single/double quotes.
- [ ] Emit `REST_ARRAY_ACCESS` with `location=unknown`; preserve line/evidence data. Do not map it to `form`, `json`, or `query` at static-analysis time.
- [ ] Keep local-array reads and non-REST PHP arrays out of this evidence class.
- [ ] Teach `parameter_seeds.py` and the REST policy in `pipeline.py` to retain the name as an unresolved candidate with evidence kind `rest_array_access_name_only`, while keeping it blocked until runtime transport evidence exists.
- [ ] Add regression coverage for `isset`, direct read, duplicate access, nested keys, and a non-REST negative control.
- [ ] Run the extractor and REST policy tests; verify the candidate name is retained but `fuzzable=false` before runtime evidence.

**Checkpoint:** static analysis now answers “callback reads key `id`” only. It must not answer “`id` is POST form” by itself.

---

## Task 4: Add isolated REST probe variants for unresolved schema parameters

**Files:**

- Modify `fuzzer/hook_energy/seed_generation/pipeline.py`.
- Modify `fuzzer/hook_energy/seed_generation/config_exporter.py`.
- Modify `fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py`.
- Add/extend tests in `fuzzer/tests/test_seed_generation_live_export.py` and `fuzzer/tests/test_zend_discovery.py`.

- [ ] For a non-path REST schema parameter whose static source is unresolved, generate probe metadata separately from the final fuzz seed. For POST, create independent form and JSON candidates; never send both in one probe.
- [ ] Generate a deterministic typed sentinel from the schema (`integer=1`, `number=1`, `boolean=true`, `string=probe`) only for non-security names. Keep the probe value out of persisted fuzz values and redact it in reports.
- [ ] Export probe configs as replay-only requests containing the candidate parameter, while retaining the original final-export gate. A probe may reach the callback and return an application error; that is not a failure of parameter discovery.
- [ ] Carry the exact pass/request identity through each probe. Do not merge evidence from form and JSON variants into one parameter unless one location is uniquely observed.
- [ ] Keep path parameters and already proven runtime locations on the existing path.
- [ ] Add tests proving a LearnPress-like `id` schema produces isolated POST probes, that probe values do not become fuzzable without runtime proof, and that form/JSON ambiguity remains blocked.
- [ ] Run exporter tests and inspect generated probe metadata for absence of raw values in persisted enrichment artifacts.

**Checkpoint:** the system can trigger `isset($request['id'])` even when the endpoint has no pre-existing fuzz body, but it still fails closed if neither POST bucket yields attributed runtime evidence.

---

## Task 5: Harden Zend normalization and final export gates

**Files:**

- Modify `fuzzer/zend_discovery/engine.py`.
- Modify `fuzzer/zend_discovery/rest_runtime.py` only where needed for the new overflow/target-membership gate.
- Modify `fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py`.
- Update `fuzzer/zend_discovery/AGENT_HANDOFF.md`.
- Extend `fuzzer/tests/test_zend_discovery.py`.

- [ ] Require the exact canonical callback identity to appear in `target_loading.loaded_callbacks`; a non-empty `file_target_count` or partial registry status alone is insufficient.
- [ ] Reject REST enrichment when `dropped_event_count > 0` for the relevant Zend request. Record a deterministic block reason such as `zend_event_buffer_overflow`.
- [ ] Preserve the existing rule that UOPZ-only POST `get_param` observations cannot establish form/JSON transport.
- [ ] Ensure callback-attributed C events for `POST -> id` normalize to exactly one `form` location and carry the existing route/method/request identity.
- [ ] Export `body_params.id` with the fuzz marker only after normalized runtime evidence is present; otherwise keep `config_type=replay_only` and `fuzzing_ready=false`.
- [ ] Update handoff documentation with the new target-loading completeness contract and the distinction between probe replay and final fuzz export.
- [ ] Run all focused Zend tests, including the existing negative controls for schema-only, method-only, name-only, and UOPZ-only POST evidence.

**Checkpoint:** no source-only `id` candidate can bypass the runtime proof gate, while a correctly attributed C event can produce a final fuzzable parameter.

---

## Task 6: Live LearnPress verification and regression pass

**Files/artifacts:** no production source change; use a fresh isolated output directory and the existing WordPress runtime.

- [ ] Rebuild/restart the WordPress Zend image so the new extension is active.
- [ ] Run the LearnPress generated flow through `phuzz.ps1` with `-Mode generated -PluginSlug learnpress -UseZendDiscovery -NoFollowLogs -KeepDebugArtifacts`.
- [ ] Verify in the fresh artifacts that `target_loading.loaded_callbacks` contains `LP_Jwt_Lessons_V1_Controller::finish_lesson`, target loading is complete, and `dropped_event_count=0`.
- [ ] Verify the C artifact contains a callback-attributed REST event for bucket `POST`, parameter `id`, path `["POST","id"]`, and the exact canonical callback.
- [ ] Verify the bridge/enrichment summary contains `id` exactly once, location `form`, `fuzzable=true`, and `final_fuzz_export_allowed=true`; verify the generated config contains `body_params.id` and is `fuzzing_ready`.
- [ ] Treat LearnPress’s business response such as “lesson is not assigned in the Course” separately: callback/parameter discovery may PASS while application-level lesson state remains an error.
- [ ] Replay the generated config with a fresh request identity and verify callback reachability plus `id` propagation again; do not reuse the Pass 1 request ID.
- [ ] Run the focused Python suite, then the full test suite. Report exact pass/fail counts and any unrelated pre-existing failures.

**Definition of done:** the current LearnPress run proves target loading, C attribution, REST transport, parameter export, and replay independently. A zero-row DB is not silently treated as a successful lesson workflow, and no final fuzz config is emitted when any of those proof stages is absent.

## Final self-review before implementation

- [ ] Every source change has a corresponding failing regression test or an explicit live-artifact assertion.
- [ ] No plan step relies on a plugin-specific callback name in production logic.
- [ ] No unresolved REST location is converted to a fuzzable location without runtime evidence.
- [ ] Overflow, duplicate registration, callback execution, and application error remain separately observable.
- [ ] The implementation preserves request/run identity separation and fresh replay request IDs.
