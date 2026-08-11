# Zend parameter enrichment in legacy generated flow

## Goal

Replace the public standalone `zend-discovery` workflow with an opt-in bridge:

```text
legacy candidates -> Pass 1 replay -> offline Zend enrichment
-> in-memory enriched-seed merge -> legacy final export -> Pass 2 replay
```

`phuzz.ps1 -Mode generated -UseZendDiscovery` creates one `legacy_run_id` for
both replay passes. Generated mode without the switch retains the existing
`export_cli.py -> seed_to_config_cli.py` behavior.

## Ownership

The legacy generated runner owns Docker, WordPress/auth setup, candidate
generation, both HTTP replay passes, temporary Pass 1 artifacts, config export,
and replay summaries. Zend is an offline enrichment library/CLI: it accepts a
selected plugin ZIP and digest, raw legacy registry/seeds, explicit current-run
Pass 1 artifacts, a run ID, and an output directory. It never starts Docker,
sends HTTP, performs auth, exports configs, or replays requests.

## Identity and evidence

Each candidate has a deterministic `canonical_identity_id` built from
`plugin_slug`, entrypoint type, dispatch identity, stable callback ID, resolved
method, and auth variant. REST dispatch includes namespace, route pattern,
endpoint-definition index, and materialized route. AJAX/admin-post dispatch
includes dispatcher kind and action. No candidate is deduplicated merely by
callback.

`X-HookPhuzz-Run-ID` is fixed for the invocation. `X-Fuzzer-Covid` is fresh for
every request; if `X-HookPhuzz-Request-ID` remains present, it has the same
value. UOPZ artifacts record both IDs. Zend accepts a Pass 1 artifact only when
run, request, plugin, canonical identity, callback, method, and auth variant
all agree. Pass 2 has a different request ID and must prove the same run and
canonical identity.

## Gates and parameters

`probe_replay_allowed` admits a replay-only Pass 1 request based on legacy
route/method/dispatch/auth/bootstrap capability, independently of fuzz fields.
`final_fuzz_export_allowed` is evaluated only after enrichment and requires
valid Pass 1 callback proof, unchanged identity/method, a nonempty safe fuzz
field set, proven transport, and legacy exporter support.

Pass 1 keeps dispatch selectors, materialized route values, and benign required
bootstrap values fixed. Auth cookies, nonces, sessions, authorization headers,
and security selectors remain in the legacy auth layer and never become Zend
inputs or fuzz fields.

Zend combines bounded static extraction, REST schema, and current-run runtime
evidence. Static and schema evidence propose names but never prove runtime reach
or transport. Direct current-run `$_GET` and `$_POST` reads may prove query and
form transport. Runtime query/form/JSON observations may prove their matching
transport. REST `get_param()` and schema-only fields remain location `unknown`.
`$_REQUEST`, HTTP method alone, and unsupported JSON export remain blocked.
Submitted values are not persisted.

## Artifacts and validation

Zend writes only `fuzzer/output/zend-discovery/<legacy-run-id>/` with an
endpoint catalog, enriched-seed aggregate, summary, and individual seeds named
by canonical identity plus method. Raw `suggested_seeds.json` remains unchanged.
The legacy adapter merges raw and enriched records in memory, drops every
unproven/blocked/empty candidate from final export, then uses the existing
exporter and generated runner for Pass 2.

PASS requires correlation, callback proof, correct transport, redaction, and
fresh Pass 2 replay evidence. HTTP status alone is never proof.
