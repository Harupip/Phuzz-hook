# Zend Direct Runtime Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Implement Stage 1 value-free direct Zend GET/POST runtime discovery for opt-in generated WordPress replay.

**Architecture:** Preserve the legacy generated export path, with an opt-in action-only Pass 1. A bridge prepares a callback registry, correlates raw UOPZ/Zend artifacts into normalized evidence, and validates a fresh Pass 2 observation before exporting configs.

**Tech Stack:** Python stdlib, PowerShell, Docker Compose, existing Phase 9 Zend extension and UOPZ instrumentation.

## Global Constraints

- Default generated mode is unchanged; `-UseZendDiscovery` requires generated mode and `-RunGeneratedConfigs`.
- Only direct, top-level Zend `GET`/`POST` rows at `helper_depth == 0` are accepted.
- No parameter source may be static extraction, source materialization, schema, request snapshot, REST, JSON, cookie, `REQUEST`, or submitted values.
- Raw schema is read-only; normalized value-free evidence is the sole generator input.
- Preserve unrelated dirty work and never modify Phase 9 extension source.

---

### Task 1: Runtime-only Pass 1 seed export

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/generator.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/export_cli.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/seed_to_config_cli.py`
- Test: `phuzz-main/code/fuzzer/tests/test_seed_generation_live_export.py`

- [ ] Add a failing test whose injected `InputSignatureExtractor` raises and assert runtime-only generation still yields an AJAX action-only replay seed.
- [ ] Run the focused test and confirm failure because runtime-only mode does not exist.
- [ ] Add the smallest flag that bypasses extractor construction/calls while retaining WordPress endpoint metadata and fixed action.
- [ ] Add the internal CLI flag and run the focused test successfully.

### Task 2: Strict normalized Zend evidence and bridge operations

**Files:**
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_bridge.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_bridge_cli.py`
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

- [ ] Add failing tests for direct GET-to-query and POST-to-form evidence plus every excluded source/path/depth/identity case.
- [ ] Run them and confirm they fail against the current static-enrichment implementation.
- [ ] Replace source materialization and extractor use with strict correlation over registry, UOPZ artifact, and Zend event summaries.
- [ ] Emit only normalized value-free evidence and patches with `method_confidence=runtime_observed`; rerun focused tests.

### Task 3: Runner target, artifact lifecycle, and Pass 2 verification

**Files:**
- Modify: `phuzz-main/code/scripts/wordpress/run-wordpress-phuzz.ps1`
- Modify: `phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php` only if registry wiring requires it
- Test: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`
- Test: `phuzz-main/code/fuzzer/tests/test_phuzz_wrapper_contract.py`

- [ ] Add failing behavioral tests for opt-in Compose override, Pass 1 action-only export, registry preparation, raw log preservation, and fresh Pass 2 request ID.
- [ ] Run them and confirm the missing Stage 1 contract.
- [ ] Add the isolated Compose override, `/shared/opcode-events` handling, and bridge calls; preserve default execution path.
- [ ] Write short proof and separate logs; rerun runner/wrapper tests.

### Task 4: Config-contract and security regressions

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/config_exporter.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py`
- Test: `phuzz-main/code/fuzzer/tests/test_seed_to_config_exporter.py`
- Test: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`

- [ ] Add failing tests that fixed action/auth bootstrap wins and artifacts containing forbidden static/value markers are rejected.
- [ ] Implement fail-closed provenance/validation without changing the default exporter’s behavior.
- [ ] Run relevant unit suites.

### Task 5: Docker fixture acceptance and regression verification

**Files:**
- Modify/create only the existing generated-config Docker fixture and its runner test support as required.

- [ ] Add fixture callback direct reads `$_GET['x'] ?? null` and `$_POST['y'] ?? null`.
- [ ] Run bounded Compose proof: Pass 1 evidence has query `x` and form `y`; Pass 2 re-observes both under a fresh request ID.
- [ ] Run the focused suite, baseline generated-flow suite, `git diff --check`, and preserve result artifacts.
