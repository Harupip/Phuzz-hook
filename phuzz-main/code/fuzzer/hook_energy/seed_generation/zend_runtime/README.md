# Zend runtime seed generation

This folder contains the Zend bridge shared by online-linked.

Reviewed 2026-10-09. The [current architecture](../../../../docs/reference/architecture.md)
and [online-linked guide](../../../../docs/guides/online-linked-flow.md) take
precedence over historical generated-mode instructions. Paths below are relative
to the `fuzzer` root, except `bridge_cli.py` in this folder.

- `seed_generation/skeleton/candidate_generator.py` creates bootstrap candidates from runtime coverage and registration metadata.
- `cli/export_zend_seeds.py` exports those candidates without copying or scanning plugin source.
- `bridge_cli.py` correlates Pass 1/Pass 2 UOPZ artifacts with Zend evidence and runs convergence helpers.
- `artifacts/retention/generated_runs.py` owns the generated-run retention API.

Runtime contract:

- Direct `$_REQUEST['name']` reads are accepted only when the same correlated
  request identifies one canonical transport: `GET/query` or `POST/form`.
- Ambiguous, JSON-only, unsupported, or uncorrelated `REQUEST` evidence is
  rejected. Pass 2 uses the same resolver as Pass 1.

Current admission can use helper-attributed reads and correlated `isset`/`empty`
presence when exact request/callback/source/transport evidence supports them.
A guard without the request key remains pending; raw guards are not renamed reads.
COOKIE discovery is opt-in via Python `--runtime-cookie-probes`; PowerShell does
not enable it. REST provenance retains query/form/JSON/path distinctions.
Pending probe discovery can consume correlated HTTP 400–599 reads, without
relaxing final readiness/replay/Pass 2 gates.

Retention contract:

The following is the **generated-run API** contract, not automatic online-linked
pruning. The current PowerShell runner has no `-KeepDebugArtifacts` flag and
keeps host online-linked campaign history.

- Success statuses: `PASS`, `SUCCESS`, `CONVERGED`, and
  `PASS_PARTIAL_AUTH_EXPECTED` prune registry, Pass 1, target, iteration, log,
  and current-run discovery artifacts after final replay succeeds.
- Success keeps `zend_convergence_summary.json`, `final/`, the final replay
  summary, and usable generated configs/summaries.
- Failure or timeout preserves the full current run tree.
- API `keep_debug_artifacts=True` preserves success-run intermediates.
- Run directory names use `<plugin-slug>-<timestamp>Z`; the wrapper currently
  uses host-local `Get-Date`, so the suffix alone does not prove UTC.
  `legacy_run_id` remains a compatibility identifier.

## Runtime CmpLog contract

CmpLog is runtime-only enrichment of the existing Zend artifact. It is enabled
by the online-linked runner with `HOOKPHUZZ_CMPLOG=1`; standalone fuzzer use
defaults to disabled without that setting. It does not
change the normal candidate, convergence, or replay contracts.

The vertical slice is:

```text
HTTP input
  -> Zend provenance
  -> PHP comparison
  -> comparison_events[] in /shared/opcode-events/<request_id>.json
  -> Fuzzer._ingest_cmplog_hints()
  -> normalize_comparison_events()
  -> ff_mutate() consumes a normalized hint
  -> replay
```

The Zend extension currently observes `IS_EQUAL`, `IS_NOT_EQUAL`,
`IS_IDENTICAL`, `IS_NOT_IDENTICAL`, and the available `SWITCH_STRING` opcode.
Fixture/VLD evidence on PHP 8.2.10 showed that string switches disassemble to
`SWITCH_STRING` and a jump table before optimization, while the active runtime
artifact exposed useful switch cases as `IS_EQUAL`. Do not infer switch shape
from source or assume that a switch always emits an equality opcode.

`comparison_events` is optional and additive. A useful event has this shape:

```json
{
  "request_id": "<current request>",
  "callback": "<correlated callback>",
  "opcode": "IS_IDENTICAL",
  "source": "GET",
  "path": ["mode"],
  "runtime_value": "INVALID_VALUE",
  "comparison_value": "special_operation"
}
```

The extension keeps events request-local, deduplicates identical events, caps
the event count and scalar value size, and preserves nested paths. Provenance
can survive the supported intermediate-variable assignments/casts, but it may
be lost by unsupported transformations. Comparisons are recorded only when at
least one operand is already linked to request input; constant-vs-constant and
uncorrelated comparisons are ignored. Sensitive-looking parameter names and
empty()/isset()/type-check paths are not mutation hints.

Normalization is parameter-specific and fail-closed:

- `GET` -> `query_params`
- `POST` -> `body_params`
- `REST_QUERY` -> `query_params`
- `REST_FORM` and `REST_JSON` -> `body_params`
- `REQUEST`, `COOKIE`, and `REST_URL` do not become CmpLog mutations without
  an existing concrete transport correlation

`normalize_comparison_events(artifact, fuzz_params)` verifies the request ID,
opcode, scalar operands, source/path, current observed value, fuzzable
parameter, and sensitive-name policy. It returns deduplicated hints carrying
request ID, callback, opcode, source, nested path, observed value, candidate
value, and `reason=cmplog`.

`Fuzzer._ingest_cmplog_hints()` performs artifact ingestion before mutation.
`apply_cmplog_hint()` receives only an already-normalized hint and applies it
to that same parameter. Keep artifact parsing out of `Fuzzer.ff_mutate()`.
Generated candidates retain `mutation_source=cmplog` and `cmplog_hint` metadata;
normal PHUZZ mutations remain available and retain `mutation_source=normal`.

Do not use CmpLog to solve authentication, nonce checks, secondary required
parameters, or arbitrary value transformations. Do not add discovered strings
to a global dictionary, seed corpus, or plugin-specific implementation. The
LearnPress values `last30days` and `custom` are acceptance-oracle values only;
they may appear in an experiment only after the runtime has discovered them.

Focused verification:

```powershell
# From phuzz-main/code, with a writable temporary directory
python -B -c "import subprocess,sys; r=subprocess.run([sys.executable,'-B','-m','unittest','fuzzer.tests.test_cmplog','fuzzer.tests.test_cmplog_extension'],timeout=180); sys.exit(r.returncode)"
php -l fuzzer/tests/fixtures/hookphuzz-cmplog-fixture.php
```

The fixture covers strict/normal/reversed comparisons, string switch dispatch,
constant and unprovenance negative controls, deduplication, and two-parameter
non-crossing. The PHP extension must also be built and exercised in the local
Docker runtime before claiming an end-to-end proof.

Do not add `InputSignatureExtractor` or `SourcePathResolver` imports here. Static source extraction lives in `seed_generation/source_assisted/` and `cli/export_seeds.py`, outside runtime-only discovery.
