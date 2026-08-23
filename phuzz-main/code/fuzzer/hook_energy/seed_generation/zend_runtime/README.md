# Zend runtime seed generation

This folder is the runtime-only Zend/UOPZ boundary.

- `candidate_generator.py` creates bootstrap candidates from runtime coverage and registration metadata.
- `export_cli.py` exports those candidates without copying or scanning plugin source.
- `bridge_cli.py` correlates Pass 1/Pass 2 UOPZ artifacts with Zend evidence and runs convergence helpers.
- `artifact_retention.py` prunes only current-run Zend intermediates after terminal success.

Runtime contract:

- Direct `$_REQUEST['name']` reads are accepted only when the same correlated
  request identifies one canonical transport: `GET/query` or `POST/form`.
- Ambiguous, JSON-only, unsupported, or uncorrelated `REQUEST` evidence is
  rejected. Pass 2 uses the same resolver as Pass 1.

Retention contract:

- Success statuses: `PASS`, `SUCCESS`, `CONVERGED`, and
  `PASS_PARTIAL_AUTH_EXPECTED` prune registry, Pass 1, target, iteration, log,
  and current-run discovery artifacts after final replay succeeds.
- Success keeps `zend_convergence_summary.json`, `final/`, the final replay
  summary, and usable generated configs/summaries.
- Failure or timeout preserves the full current run tree.
- `-KeepDebugArtifacts` preserves all success-run intermediates.
- The public run-directory name is `<plugin-slug>-<UTC timestamp>`; the
  existing `legacy_run_id` field/argument remains only for compatibility.

## Runtime CmpLog contract

CmpLog is an opt-in, runtime-only enrichment of the existing Zend artifact. It
is enabled by the generated Zend runner with `HOOKPHUZZ_CMPLOG=1` and does not
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
rtk python -m unittest fuzzer.tests.test_cmplog fuzzer.tests.test_cmplog_extension
rtk php -l fuzzer/tests/fixtures/hookphuzz-cmplog-fixture.php
```

The fixture covers strict/normal/reversed comparisons, string switch dispatch,
constant and unprovenance negative controls, deduplication, and two-parameter
non-crossing. The PHP extension must also be built and exercised in the local
Docker runtime before claiming an end-to-end proof.

Do not add `InputSignatureExtractor` or `SourcePathResolver` imports here. Static source extraction lives in the parent seed-generation path (`static_generator.py` and `export_cli.py`) and is not part of `-UseZendDiscovery`.
