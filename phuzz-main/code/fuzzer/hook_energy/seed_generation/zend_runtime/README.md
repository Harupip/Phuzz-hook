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

Do not add `InputSignatureExtractor` or `SourcePathResolver` imports here. Static source extraction lives in the parent seed-generation path (`static_generator.py` and `export_cli.py`) and is not part of `-UseZendDiscovery`.
