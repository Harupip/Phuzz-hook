# Zend Photo Gallery Runtime Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve correlated helper-originated AJAX parameter candidates, probe each transport, and admit only correlated read evidence into fuzzable config.

**Architecture:** Keep raw Zend summaries/events as candidate evidence with real helper depth. Centralize direct GET/POST acceptance checks around operation, callback attribution, request bucket, and run/request/plugin/method correlation. Let the bridge emit bounded probe variants; let the online-linked coordinator execute those probes and only then perform export, replay, and Pass 2.

**Tech Stack:** Python `unittest`, JSON runtime artifacts, existing PowerShell/Docker wrapper (runtime not run in this change).

**Spec:** User request in this conversation.

## Global Constraints

- Candidate is not known/fuzzable until correlated Zend `read` and request-key evidence exist.
- Preserve actual `helper_depth`; do not infer provenance from depth or function name.
- Scope first step to flat GET/POST; probe GET and POST separately.
- Keep action, auth context, and correlated request values; probe values are explicitly marked `probe`.
- No new C instrumentation, Docker/runtime execution, commit, or push.
- Preserve unrelated dirty/generated files.

---

### Task 1: Add failing runtime evidence regressions

**Files:**
- Modify: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- Modify: `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`

**Interfaces:** Tests exercise existing normalization/convergence/Pass 2/coordinator boundaries and define candidate, accepted, rejection, transport, probe, and worker contracts before implementation.

- [ ] Add fixture-driven tests for helper `isset` candidate, helper `read` acceptance with exact request bucket, mismatched correlation/attribution, missing request key, separate GET/POST probes, and probe failure preserving parent state.
- [ ] Run focused tests with a 30-second process timeout and confirm expected failures caused by missing behavior.

### Task 2: Centralize candidate/accepted direct Zend evidence

**Files:**
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- Modify: `phuzz-main/code/fuzzer/seed_generation/convergence/convergence.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py`

**Interfaces:** `normalize_runtime_evidence()` emits accepted rows plus diagnostic candidate rows; `canonical_runtime_parameter_identity()` admits accepted rows only; convergence returns candidate/probe diagnostics while materializing only accepted rows.

- [ ] Preserve flat GET/POST rows from correlated raw Zend summaries/events, retain real helper depth, and mark helper `isset` rows pending rather than fuzzable.
- [ ] Accept only matching `read` operation plus key in exact query/form bucket; reject ambiguous/missing transport and incomplete attribution.
- [ ] Materialize bounded AJAX probe variants from runtime candidate `(source,name)`, with explicit probe provenance and no fuzz selectors.

### Task 3: Execute pending probes in online-linked coordinator

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_coordinator.py`
- Do not modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_config_runner.py` unless a focused test proves it is on this Photo Gallery path.

**Interfaces:** `advance_online_version()` handles `pending_probes` before `NO_NEW_ZEND_PARAMETER`; probe replay is bounded, deduped, and failure-coded; parent `known_parameters` changes only after child export/replay/Pass 2 succeeds.

- [ ] Stop/replay/restart parent around one probe at a time, retaining action/auth/fixed values and correlating probe run/request IDs.
- [ ] Feed successful probe artifacts back through convergence, then use existing child export/replay/Pass 2 handoff.
- [ ] Record raw-candidate, pending, rejected, probe-failed/budget, and accepted counts/reasons without changing terminal status meanings unnecessarily.

### Task 4: Verify offline and report runtime command/checklist

**Files:**
- No artifact edits.

- [ ] Run focused and full offline unittest suites with explicit timeouts, plus Python compile and diff checks.
- [ ] Inspect final diff/status and confirm unrelated WIP is unchanged.
- [ ] Report exact wrapper command from `scripts/wordpress/run-wordpress-phuzz.ps1`; separate offline verification from unrun Photo Gallery runtime proof.
