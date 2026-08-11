# Zend Discovery Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an isolated, conservative Zend/UOPZ discovery workflow for one local plugin ZIP.

**Architecture:** A pure Python engine turns UOPZ request registry/artifacts into an endpoint catalog, proof-correlated PHUZZ configs, and immutable run summaries. PowerShell exposes it as an opt-in mode and preserves every legacy branch.

**Tech Stack:** Python standard library, unittest, PowerShell, existing PHUZZ config schema.

## Global Constraints

- Do not call or modify Phase 10–13.
- Do not download plugin ZIPs or delete `fuzzer/output/*`.
- Reject stale, cross-plugin, mismatched endpoint/method/callback evidence.
- Persist no recipe secret, cookie, or password values.

---

### Task 1: Pure discovery engine

**Files:**
- Create: `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- Create: `phuzz-main/code/fuzzer/zend_discovery/__init__.py`
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

- [ ] Write failing tests for ZIP metadata, target ownership, conservative selection, and evidence correlation.
- [ ] Run `python -m unittest fuzzer.tests.test_zend_discovery` and observe missing-module failure.
- [ ] Implement ZIP validation and pure normalization/filter/correlation helpers.
- [ ] Run the same tests to green.

### Task 2: Immutable artifacts and recipe boundary

**Files:**
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

- [ ] Write failing tests for run output layout, config generation, blocked status, and unsafe recipe rejection.
- [ ] Implement `run_discovery` and CLI with explicit stage statuses.
- [ ] Run the test module to green.

### Task 3: Guided wrapper

**Files:**
- Modify: `phuzz-main/code/phuzz.ps1`
- Modify: `phuzz-main/code/fuzzer/tests/test_phuzz_wrapper_contract.py`

- [ ] Write failing wrapper tests for mode validation, ZIP selector, and dry-run dispatch.
- [ ] Add the `zend-discovery` branch only; leave existing branch commands intact.
- [ ] Run wrapper and discovery tests to green.

### Task 4: Verification

**Files:**
- Verify: changed files

- [ ] Run targeted unittest modules, Python compilation, PowerShell parser, and `git diff --check`.
- [ ] Re-read plan constraints against the final diff.
