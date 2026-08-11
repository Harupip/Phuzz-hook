# Zend Discovery Engine Design

## Goal

Add an opt-in `zend-discovery` workflow that runs one local WordPress plugin ZIP, catalogs target-owned AJAX and REST registrations, probes only conservative endpoints, then creates PHUZZ configs only from correlated runtime proof.

## Boundaries

- Legacy `default`, `seed-config`, `generated`, and `recursive` paths remain unchanged.
- No Phase 10–13 script, artifact, or gate is called.
- One plugin ZIP per run; no downloads.
- `fuzzer/output/zend-discovery/<run-id>/` is newly created and never cleaned by this mode.
- REST GET/HEAD and read-like AJAX actions are the only automatic probes. State, nonce, and authenticated recipe needs stay blocked.

## Components

`fuzzer/zend_discovery/engine.py` owns ZIP validation, registry normalization, ownership filtering, conservative probing, artifact correlation, config generation, and immutable JSON output. Its CLI consumes externally supplied UOPZ request artifacts, which keeps the decision layer unit-testable. `phuzz.ps1` supplies a `zend-discovery` option and dispatches only the new CLI.

Existing UOPZ request files already record callback source, method, request ID, target plugin, REST metadata, and parameters. The engine treats those fields as proof only when all selected-plugin/run/endpoint/callback/method conditions agree.
