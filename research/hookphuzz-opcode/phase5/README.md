# HookPhuzz opcode research — Phase 5

Phase 5 is an isolated Apache/mod_php proof that direct request-superglobal opcode observations can be emitted as request-local JSON artifacts. It does not load Phase 1–4, WordPress, UOPZ, HookPhuzz, config generation, or replay code.

Run from the repository root:

```bash
bash research/hookphuzz-opcode/phase5/run.sh
```

The host needs Docker only. The build uses `php:8.2.10-apache`; it compiles and loads the extension inside the image. JIT and OPcache are disabled for all semantic runtime checks.

## Architecture and lifecycle

`enabled` and `disabled` Apache containers serve the same fixture directory. The enabled target loads only `hookphuzz_opcode_phase5`; the disabled target is the semantic baseline. A verifier container sends requests, validates artifacts from the shared Docker volume, and writes result files into `phase5/results/`.

The extension registers only `ZEND_FETCH_R`, `ZEND_FETCH_DIM_R`, `ZEND_FETCH_IS`, `ZEND_FETCH_DIM_IS`, and `ZEND_ISSET_ISEMPTY_DIM_OBJ`. Provenance is copied metadata keyed by `(execute frame, result.var)`: HTTP source plus string/integer path. Frame-end cleanup removes only provenance owned by that completed user execute frame.

At `RINIT`, the extension resets request state and reads `X-Fuzzer-Covid` from the SAPI request-header API, never from fixture user code. At `RSHUTDOWN`, it flushes one JSON artifact, then releases events and provenance. It never retains zval pointers or request values.

Valid request IDs match `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. Missing, invalid, or duplicate IDs do not write an artifact; this avoids a fallback collision, path traversal, and overwrite. The reason is logged by Apache. Query values in `uri` are replaced with `<redacted>` before they enter extension state.

Artifacts are written to `/shared/opcode-events/<request-id>.json` using a temporary file, `fsync`, close, and Linux `renameat2(..., RENAME_NOREPLACE)`. A duplicate final path is preserved, not replaced.

## Artifact schema

```json
{
  "schema_version": 1,
  "request_id": "get-literal",
  "pid": 123,
  "method": "GET",
  "uri": "/get-literal.php?get_literal=<redacted>",
  "event_count": 1,
  "dropped_event_count": 0,
  "events": [
    {
      "source": "GET",
      "path": ["get_literal"],
      "operation": "read",
      "file": "/var/www/html/get-literal.php",
      "line": 4,
      "function": "phase5_get_literal",
      "class": null
    }
  ]
}
```

Only mapped source/path metadata is exported. Cookie, POST, GET, and other request values are never exported; integer keys remain integers in `path`.

## Results

The runner creates `environment.txt`, HTTP/concurrency/stability/event-cap/semantic summaries, `sample-events.json`, and `final-verdict.txt` in `results/`. It prints only `PHASE_5_PASS` after all gates pass. On failure it prints `PHASE_5_FAIL` with the failing test, expected/actual result, log path, and a root-cause hypothesis.

## Limits and deferred scope

This proves direct opcode-slot reads under Apache only. It does not prove complete dynamic parameter discovery and deliberately excludes assignment aliases, references, argument/return propagation, properties, ArrayAccess provenance, arbitrary dataflow, `filter_input`, JSON bodies, WordPress, UOPZ, HookPhuzz integration, config generation, and replay.
