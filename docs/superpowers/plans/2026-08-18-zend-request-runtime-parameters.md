# Zend `$_REQUEST` Runtime Parameters Implementation Plan

> **For agentic workers:** Execute these steps task-by-task with review checkpoints. Do not use static source extraction, broad `REQUEST` acceptance, or unrelated refactors.

**Goal:** Promote safe, correlated Zend `$_REQUEST` reads into existing `GET/query` or `POST/form` runtime parameter contracts so the comment plugin can generate and verify final fuzz configs.

**Architecture:** Add one transport-resolution helper at the runtime evidence boundary. `normalize_runtime_evidence` and Pass 2 verification both call it and emit/compare only canonical `GET` or `POST` evidence; convergence and config generation remain unchanged. Ambiguous or unsupported `REQUEST` reads remain excluded.

**Tech Stack:** Python 3, `unittest`, existing Zend/UOPZ JSON artifacts, PowerShell Docker runner.

**Spec:** `docs/superpowers/specs/2026-08-18-zend-request-runtime-parameters.md`

## Global Constraints

- Keep the Zend path runtime-only; do not call `InputSignatureExtractor` or read plugin source for this feature.
- Preserve existing direct `GET`/`POST`, auth skip, convergence, callback verification, final replay, and artifact retention contracts.
- Do not add a plugin-specific rule for `show-all-comments-in-one-page`.
- Do not alter or delete unrelated WIP, generated debug artifacts, fixtures, or source files.
- Do not commit or push; leave the working tree uncommitted for review.

---

### Task 1: Add failing transport-resolution and normalization tests

**Files:**
- Modify: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

**Interfaces:**
- Consumes: existing `normalize_runtime_evidence` and `verify_pass2_contract` test helpers.
- Produces: failing regression tests that define the canonical `REQUEST -> GET/POST` contract.

- [ ] **Step 1: Add POST `REQUEST` normalization test**

Use a correlated AJAX candidate with `request_method="POST"`, form content type, and a Zend callback summary containing:

```python
{"source": "REQUEST", "path": ["post_type"], "helper_depth": 0, "observed_count": 1}
```

Assert the normalized result contains exactly:

```python
{"name": "post_type", "source": "POST", "location": "form", "fuzzable": True}
```

- [ ] **Step 2: Add GET `REQUEST` normalization test**

Use the same evidence with a `GET` candidate and assert `source="GET"`, `location="query"`.

- [ ] **Step 3: Add ambiguity rejection test**

Put the same parameter name in both correlated query and body transport metadata. Assert that the `REQUEST` evidence is omitted rather than guessed.

- [ ] **Step 4: Add Pass 2 raw-event compatibility test**

Create a merged seed expecting `(post_type, POST, form)`, a Pass 2 Zend callback summary reporting raw `REQUEST[post_type]`, and a callback-reached UOPZ artifact. Assert:

```python
verify_pass2_contract(...) == {"accepted": 1, "total": 1}
```

- [ ] **Step 5: Run the new tests and confirm they fail for the current implementation**

Run from `phuzz-main/code`:

```powershell
python -m unittest fuzzer.tests.test_zend_discovery
```

Expected: the new `REQUEST` tests fail because the current allowlists accept only `GET` and `POST`.

### Task 2: Implement shared `REQUEST` transport resolution at the runtime boundary

**Files:**
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py:89-180`
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

**Interfaces:**
- Consumes: correlated candidate, UOPZ request artifact, Zend request method/content metadata, and direct callback summary evidence.
- Produces: existing normalized rows with `source` in `{"GET", "POST"}` and `location` in `{"query", "form"}`.

- [ ] **Step 1: Add a small resolver with an explicit return contract**

Implement a helper equivalent to:

```python
def resolve_request_transport(
    name: str,
    *,
    request_method: str,
    request_params: Mapping[str, Any],
    headers: Mapping[str, Any],
) -> tuple[str, str] | None:
```

Use this precedence:

1. If `name` exists in exactly one of `query_params` or `body_params`, return `("GET", "query")` or `("POST", "form")` respectively.
2. If no exact transport key exists and method is `GET`, return `("GET", "query")`.
3. If no exact transport key exists and method is `POST` with `application/x-www-form-urlencoded` or `multipart/form-data`, return `("POST", "form")`.
4. Return `None` for both transports, JSON-only/unsupported methods, or ambiguous presence.

Do not return values from the artifact; this helper resolves only transport identity.

- [ ] **Step 2: Use the resolver only for direct `REQUEST` events**

Keep the existing `GET`/`POST` branches unchanged. For `REQUEST`, require the existing scalar path, helper depth, positive count, and correlation gates before calling the resolver. Emit canonical evidence:

```python
{
    "source": resolved_source,
    "location": resolved_location,
    "evidence_kind": "zend_runtime",
    "fuzzable": True,
}
```

- [ ] **Step 3: Run the Task 1 tests and verify they pass**

```powershell
python -m unittest fuzzer.tests.test_zend_discovery
```

Expected: normalization tests pass; existing direct GET/POST and REST tests remain green.

### Task 3: Apply the same canonicalization to Pass 2 verification

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py:514-548`
- Modify: `phuzz-main/code/fuzzer/zend_discovery/engine.py` only if the resolver is exported there.
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

**Interfaces:**
- Consumes: raw Zend `unique_parameters`, UOPZ request transport metadata, and the canonical expected seed parameter set.
- Produces: observed identities matching the existing `(name, source, location)` Pass 2 contract.

- [ ] **Step 1: Replace the Pass 2 direct-source allowlist with the shared resolver path**

For raw `REQUEST` events, resolve transport using the same request method and request metadata used in Task 2. Add the resulting canonical tuple, for example:

```python
("post_type", "POST", "form")
```

Keep helper-depth, scalar-path, observed-count, callback, request-id, run-id, and method checks unchanged.

- [ ] **Step 2: Run the Pass 2 regression test**

```powershell
python -m unittest fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_pass2_verification_accepts_request_transport_mapping
```

Expected: `accepted=1,total=1`.

- [ ] **Step 3: Confirm no convergence/config plumbing change is required**

Because Tasks 2-3 emit canonical `POST/form` or `GET/query`, verify that `convergence.py` and the config exporter still receive their existing source/location values. Do not add a new `REQUEST` seed source.

### Task 4: Add end-to-end seed materialization regression coverage

**Files:**
- Test: `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- Test: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py` only if the final config runner contract needs an additional assertion.

**Interfaces:**
- Consumes: normalized runtime rows from Task 2 and Pass 2 verifier output from Task 3.
- Produces: proof that a `REQUEST` discovery becomes a usable final config without static extraction.

- [ ] **Step 1: Add a convergence materialization test**

Feed a converged patch containing:

```python
{"name": "post_type", "location": "form", "source": "POST", "evidence_kind": "zend_runtime"}
```

Assert the materialized seed contains `body["post_type"] == "FUZZ"`, `"post_type"` in `fuzzable_params`, and a `POST` input parameter.

- [ ] **Step 2: Assert static extraction is not needed**

Use a runtime candidate with no static input list and assert the materialized parameter still comes from `evidence_kind="zend_runtime"`.

- [ ] **Step 3: Run focused tests**

```powershell
python -m unittest fuzzer.tests.test_zend_discovery fuzzer.tests.test_generated_config_runner
```

Expected: all focused tests pass.

### Task 5: Verify the real comment-plugin Docker path

**Files:**
- No source changes.
- Inspect: `phuzz-main/code/fuzzer/output/seed_generation/zend-bridge/<new-run-id>/`

**Interfaces:**
- Consumes: existing local Docker WordPress fixture and `show-all-comments-in-one-page.zip`.
- Produces: a fresh runtime-only Zend proof with final config and Pass 2 evidence.

- [ ] **Step 1: Run the local generated Zend proof**

Use the existing local command from `phuzz-main/code`:

```powershell
.\phuzz.ps1 -Mode generated -PluginSlug show-all-comments-in-one-page -UseZendDiscovery -ZendMaxIterations 5 -GeneratedConfigTimeoutSeconds 30 -SeedWaitSeconds 30 -WebTimeoutSeconds 180 -NoFollowLogs
```

If the host PowerShell lacks `Get-FileHash`, define the existing process-local SHA-256 compatibility shim before invoking `phuzz.ps1`; do not add a repository file for the shim.

- [ ] **Step 2: Verify Pass 1 and Zend evidence**

Require:

```text
pass1 callback_reached=1
expected_auth_skip=1
Zend target callback=wp_ajax_sac_post_type_call
Zend observed post_type/post_category/post_id
```

- [ ] **Step 3: Verify final materialization**

Require the final generated config summary to contain one authenticated config whose body includes the discovered form parameters and whose metadata has `fuzzing_ready=true`.

- [ ] **Step 4: Verify Pass 2 and retention**

Require:

```text
Zend Pass 2 verification: accepted=1 total=1
terminal status = PASS_PARTIAL_AUTH_EXPECTED
```

Then confirm the successful run retains `zend_convergence_summary.json`, final config(s), and final run summary while pruning pass1/target intermediate artifacts. If any final gate fails, retain the full run tree and report the first failing artifact rather than relaxing the gate.

### Task 6: Full regression and handoff

**Files:**
- No additional source files.
- Inspect: only confirmed files changed by Tasks 1-4.

- [ ] **Step 1: Run the complete test suite**

```powershell
python -m unittest discover -s fuzzer/tests -p 'test_*.py'
```

Expected: all tests pass.

- [ ] **Step 2: Run syntax and whitespace checks**

```powershell
python -m py_compile fuzzer/zend_discovery/engine.py fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py
git diff --check
```

- [ ] **Step 3: Parse the PowerShell runner**

Use the existing PowerShell AST parser check and require `PowerShell parse OK`.

- [ ] **Step 4: Review scope**

Confirm the diff contains only the runtime resolver, Pass 2 canonicalization, focused tests, and the plan/spec documents. Confirm unrelated WIP remains untouched and do not commit.

## Handoff

After the plan is reviewed, execute it inline in this workspace with checkpoints after Tasks 2, 3, and 5. The expected success criterion is a fresh comment-plugin run that discovers `post_type`, `post_category`, and `post_id` dynamically, generates a final config, and passes Pass 2 without static source extraction.

## Execution status (2026-08-19)

Tasks 1-4 are implemented and verified:

- `engine.py` now resolves correlated direct `REQUEST` reads to the existing
  `GET/query` or `POST/form` contract, rejecting ambiguity and unsupported
  transports.
- `zend_runtime/bridge_cli.py` uses the same resolver for Pass 2.
- Focused regression coverage includes GET, POST, ambiguity rejection, Pass 2,
  and final seed materialization without static input.
- `python -m unittest fuzzer.tests.test_zend_discovery`: 75 tests passed.
- `python -m unittest discover -s fuzzer/tests -p "test_*.py"`: 304 tests passed.
- Python compile, PowerShell AST parse, and `git diff --check` passed.

Task 5 was executed twice but remains blocked by the final Docker gate. The
fresh run `show-all-comments-in-one-page-20260819T000546Z` reached Pass 1 with
`callback_reached=1` and `expected_auth_skip=1`; Zend observed
`post_type`, `post_category`, and `post_id` in iteration 0. In iteration 1 the
fresh Zend artifact omitted `post_id`, so convergence failed closed with
`REPLAY_FAILED` before final replay and retention. The run tree was preserved
for debugging. This is not a successful proof and the gate must not be
reported as PASS until the missing runtime evidence is resolved.
