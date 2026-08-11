# Zend parameter enrichment bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in, artifact-correlated Zend parameter enrichment to legacy generated mode without changing default generated behavior.

**Architecture:** A pure `zend_discovery` package converts explicit Pass 1 evidence into canonical enriched seeds. The existing PowerShell generated runner owns lifecycle: it creates replay-only Pass 1 configs, calls the offline engine, merges accepted seeds in memory, exports final configs, and runs Pass 2.

**Tech Stack:** Python standard library and unittest, PowerShell, PHP/UOPZ, existing PHUZZ configuration schema.

## Global Constraints

- `-UseZendDiscovery` is valid only with `-Mode generated`; remove public `zend-discovery` mode.
- Preserve default `generated` behavior and config exporter/generated runner semantics.
- One `legacy_run_id` per invocation; every HTTP request has a fresh `X-Fuzzer-Covid` value.
- Zend never imports or calls Docker, HTTP, auth, config exporter, or generated runner code.
- Persist no submitted parameter values, cookie/session/nonce/auth material, or secrets.
- Leave unrelated dirty files untouched.

---

### Task 1: Canonical identity and offline enrichment model

**Files:**
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- Modify: `phuzz-main/code/fuzzer/zend_discovery/parameter_seeds.py`
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

**Interfaces:**
- Produces `canonical_identity(candidate) -> dict`, `canonical_identity_id(candidate) -> str`, and `enrich_current_run(...) -> dict`.
- Consumes explicit candidate metadata and Pass 1 artifacts; returns only redacted provenance and resolved locations.

- [ ] Write failing unit tests for deterministic route/action/auth/method identity and exact run/request/plugin/callback/method/auth rejection.
- [ ] Run `python -m unittest fuzzer.tests.test_zend_discovery` and confirm the new assertions fail.
- [ ] Add canonical tuple creation and strict Pass 1 correlation without callback-only deduplication.
- [ ] Run the same command and confirm the identity/correlation tests pass.
- [ ] Write failing unit tests for direct GET/POST, runtime query/form/JSON, schema-only, `get_param`, `$_REQUEST`, method-only, redaction, and submitted-value non-persistence.
- [ ] Implement only the evidence/provenance rules required by those tests; do not infer transport from HTTP method or schema.
- [ ] Run the same command and confirm all enrichment tests pass.

### Task 2: Offline artifact contract and in-memory bridge

**Files:**
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- Create: `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_bridge.py`
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- Test: `phuzz-main/code/fuzzer/tests/test_seed_to_config_exporter.py`

**Interfaces:**
- `run_enrichment(...) -> dict` writes only Zend output artifacts.
- `merge_enriched_seeds(raw_report, enriched_report) -> dict` returns a memory-only legacy seed report accepted by the unchanged exporter.

- [ ] Write failing tests for canonical filenames, endpoint catalog, no Pass 2 ID in Zend artifacts, raw-report immutability, zero-fuzz blocking, and independent-candidate continuation.
- [ ] Run `python -m unittest fuzzer.tests.test_zend_discovery fuzzer.tests.test_seed_to_config_exporter` and confirm the new assertions fail.
- [ ] Implement output writing and merge filtering so only nonempty `final_fuzz_export_allowed` candidates reach existing export.
- [ ] Run the same command and confirm it passes.

### Task 3: Legacy two-pass orchestration and UOPZ headers

**Files:**
- Modify: `phuzz-main/code/phuzz.ps1`
- Modify: `phuzz-main/code/scripts/wordpress/run-wordpress-phuzz.ps1`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py`
- Modify: `phuzz-main/code/fuzzer/fuzzer.py`
- Modify: `phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php`
- Test: `phuzz-main/code/fuzzer/tests/test_phuzz_wrapper_contract.py`
- Test: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`

**Interfaces:**
- `-UseZendDiscovery` passes `LegacyRunId` only through generated mode.
- The legacy runner produces Pass 1 temporary summary, invokes offline enrichment, and produces the existing final Pass 2 summary.

- [ ] Write failing contract tests for mode rejection, unchanged default generated dry run, one run ID, two distinct request IDs, and no public standalone mode.
- [ ] Run `python -m unittest fuzzer.tests.test_phuzz_wrapper_contract fuzzer.tests.test_generated_config_runner` and confirm the new assertions fail.
- [ ] Add the smallest PowerShell orchestration helpers and summary metadata needed to execute Pass 1 and Pass 2 through legacy controls.
- [ ] Change UOPZ and request preparation to preserve `X-HookPhuzz-Run-ID` and set request/correlation headers to the same fresh request ID.
- [ ] Run the same command and confirm it passes.

### Task 4: Bounded integration contract and verification

**Files:**
- Modify: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- Verify: files changed by Tasks 1-3

- [ ] Add a bounded fixture contract that checks Pass 1 correlation, fixed bootstrap fields, nonempty enrichment, final config creation, fresh Pass 2 identity, transport, and redaction.
- [ ] Run focused unit tests, `python -m compileall -q fuzzer/zend_discovery fuzzer/hook_energy/seed_generation`, PowerShell parser checks, and `git diff --check`.
- [ ] If Docker is available, run the bounded fixture with an explicit outer timeout and inspect the produced artifacts; otherwise report that live proof is blocked rather than claiming PASS.
- [ ] Re-read the design and verify every gate/ownership/correlation rule is represented by a test or runtime artifact.
