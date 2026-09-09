# Online-Linked Probe Sender Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce online-linked probe and child-replay Docker overhead without weakening runtime correlation, admission, or Pass 2.

**Architecture:** A non-destructive one-shot sender runs inside the already active parent container. Request preparation is shared with `Fuzzer.prepare_request`; the sender returns one correlated artifact result, while the coordinator keeps existing verification/admission. Child handoff becomes replay-verify-stop-start.

**Tech Stack:** Python, `requests`, Docker Compose exec, unittest.

**Spec:** `docs/superpowers/specs/2026-09-09-online-linked-probe-sender-design.md`

## Global Constraints

- Preserve current query/body/JSON/cookie/auth/nonce/method/header semantics.
- Pass run/request IDs explicitly; never mutate parent environment.
- Never construct `Fuzzer` in sender mode.
- Ignore `.tmp` and require exact request/Zend correlation.
- Keep helper-derived `isset` candidate-only and existing admission/Pass 2 rules.
- Preserve WIP and old artifacts; no commit/push.

### Task 1: Lock sender and artifact contracts with failing tests

**Files:**
- Modify: `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`
- Add: `phuzz-main/code/fuzzer/tests/test_probe_sender.py`

- [x] Add tests for explicit IDs, no `Fuzzer()` construction, exact pair filtering, `.tmp` rejection, and one-shot command shape.
- [x] Add tests for probe failure/timeout preserving parent and child handoff ordering.
- [x] Run focused tests and confirm expected red failures.

### Task 2: Extract request preparation and add one-shot sender

**Files:**
- Modify: `phuzz-main/code/fuzzer/fuzzer.py`
- Modify: `phuzz-main/code/fuzzer/tests/test_probe_sender.py`

- [x] Extract only the shared request-building/auth logic used by `Fuzzer.prepare_request()`.
- [x] Add sender entrypoint that loads config without constructing `Fuzzer`, passes `run_id` and `request_id` explicitly, sends once, and does not touch parent state.
- [x] Run request semantics tests: guest/authenticated, query/form/JSON, cookies, headers, nonce, types.

### Task 3: Add single-process correlated artifact collection

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py`
- Modify: `phuzz-main/code/fuzzer/tests/test_probe_sender.py`

- [x] Add bounded sender/wait command support with one shared deadline and one final artifact payload.
- [x] Filter exact request/probe IDs before callback/method/auth/provenance verification; reuse `evaluate_artifact_payloads`.
- [x] Ensure parent/other artifacts cannot end the wait early.

### Task 4: Integrate probe and replay handoff

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_coordinator.py`
- Modify: `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`

- [x] Replace per-probe stop/replay-runner/restart with sender exec into active parent; leave V0 unchanged.
- [x] Check parent exit/VULN_FOUND before, during, and after sender wait; preserve recovery and terminal states.
- [x] Replay child while parent runs; require callback, artifact correlation, existing Pass 2, then stop parent; start child only on successful stop.
- [x] Record timing and concise hook/version/probe/parameter events.

### Task 5: Verification and handoff report

**Files:**
- No production files unless tests expose a scoped defect.

- [x] Run focused tests with bounded timeout, then broader related tests.
- [x] Run `git diff --check`, inspect diff/status, and confirm WIP/untracked artifacts unchanged.
- [x] Report pass/fail/skip, runtime UNVERIFIED if not run, timing availability, risks, and PASS/PARTIAL/BLOCKED verdict.
