# Zend Direct Runtime Discovery — Stage 1

## Goal

Add an opt-in, two-pass generated-config workflow that derives only direct top-level `$_GET` and `$_POST` parameters from correlated Zend runtime events.

## Scope

The default `export_cli.py -> seed_to_config_cli.py` flow remains unchanged. `-UseZendDiscovery` remains valid only for generated mode with `-RunGeneratedConfigs`; it does not use the entrypoint pipeline.

Pass 1 creates action-only replay candidates with legacy platform metadata, without static input extraction. The web target writes unmodified UOPZ coverage artifacts and unmodified Phase 9 Zend event files. A registry supplies `callback_id -> canonical_callback` before requests run.

The bridge independently correlates run ID, request ID, plugin, candidate, method, UOPZ callback execution, and exact Zend callback summary. It normalizes only value-free rows with source `GET` or `POST`, a single string path key, helper depth zero, positive count, and an exact canonical callback. `GET` becomes config query data and `POST` becomes form data regardless of transport method.

Pass 2 invokes production `Fuzzer.load_config` and `Fuzzer.prepare_request` with a new request ID under the same run ID. A result is accepted only when the config, request correlation, callback execution, and Zend re-observation of every accepted parameter agree.

## Explicit exclusions

No `$_REQUEST`, cookie, REST/schema, JSON, nested paths, helper propagation, static/source/schema/request-snapshot parameter discovery, submitted values, new dependencies, or Phase 9 extension changes.

## Artifacts

Only normalized evidence can feed seed/config generation. Raw UOPZ and Zend artifacts are preserved under `logs/`; the primary proof is a concise summary. Normalized and merged artifacts must not contain `static_regex`, `source_exact`, submitted values, or raw security material.
