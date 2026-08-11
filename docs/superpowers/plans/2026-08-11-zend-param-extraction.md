# Zend parameter-enrichment in the legacy generated flow

## Goal

Zend is a parameter-enrichment stage, not a Docker/HTTP/config/replay runner:

```text
legacy dynamic discovery (Pass 1)
  -> pass-1 request proof
  -> Zend static + schema + observation enrichment
  -> enriched seed adapter
  -> legacy config exporter
  -> legacy generated runner (Pass 2)
  -> pass-2 replay proof
```

Zend must never start Compose, create WordPress/UOPZ overrides, send HTTP probes,
copy/delete runtime artifacts, classify authenticated callbacks, export configs,
or replay requests.

## Correlation and candidate contracts

- Generate one `legacy_run_id` for `-Mode generated -UseZendDiscovery` and carry it
  in fixed header `X-HookPhuzz-Run-ID` through both passes. It identifies the
  logical batch only; it is **not** a request ID.
- Retain PHUZZ `X-Fuzzer-Covid` request IDs. Pass 1 and Pass 2 each create a new
  `request_id` for every HTTP request. Zend enriches only from the
  `pass1_request_id`; replay proof must have a distinct `pass2_request_id`.
- Correlation gate for Pass 1: same `legacy_run_id`, plugin, canonical candidate
  identity, callback, resolved method, and `pass1_request_id`. The Pass 2 proof
  must match the same batch/candidate identity, but not the Pass 1 request ID.
- Canonical candidate identity is:
  `plugin_slug + entrypoint_type + dispatch_identity + callback_id + resolved_method + auth_variant`.
  `dispatch_identity` is the fixed AJAX action, REST route pattern/materialized
  route, or equivalent legacy dispatcher selector. `auth_variant` distinguishes
  `wp_ajax_*` from `wp_ajax_nopriv_*` even when their action/callback match.
- Zend receives only current-run artifacts passed by legacy. It blocks missing or
  mismatched proof, source resolution failure, a legacy-unrunnable recipe, or zero
  final fuzz fields. It does not use its own read-safe/auth/method policy.

## Implementation

### 1. Wrapper and legacy two-pass lifecycle

- Remove public `-Mode zend-discovery` and its standalone Docker/probe/override/
  replay implementation. Add `-UseZendDiscovery` valid only with
  `-Mode generated`; generated mode without the flag remains byte-for-byte
  behaviorally unchanged.
- In `run-wordpress-phuzz.ps1`, generate and pass the batch `legacy_run_id`; run
  the existing entrypoint/candidate mapping for Pass 1. Continue to let legacy
  own Docker lifecycle, UOPZ login/capability/nonce behavior, runtime artifact
  collection, config execution, and cleanup.
- Build Pass-1 configs through the existing config exporter and runner, but remove
  fuzz fields. Preserve route, method, fixed action/dispatcher selectors, auth,
  and fixed bootstrap parameters required to reach the callback. Bootstrap values
  may only originate from an existing legacy candidate, REST schema default,
  known benign typed seed, or declarative legacy request recipe. Nonce/session/
  cookies remain solely the existing UOPZ/auth layer responsibility.
- Introduce two independent gates:
  - `probe_replay_allowed`: legacy can make the minimum callback-reaching request
    with a route, method, fixed dispatch identity, auth behavior, and any required
    bootstrap values. This is the Pass-1 admission gate and must not depend on
    fuzz fields.
  - `final_fuzz_export_allowed`: enrichment produced at least one safe,
    transport-proven fuzz field. This is the Pass-2 export gate.
- Keep Pass-1 summaries/configs temporary and legacy-owned. The only persisted
  replay summary is the existing Pass-2 generated-runner summary.

### 2. UOPZ evidence and Zend inputs

- Record `HTTP_X_HOOKPHUZZ_RUN_ID` in UOPZ coverage/request artifacts alongside
  the existing request-local `X-Fuzzer-Covid` value. A missing HookPhuzz header
  remains valid for legacy modes not opting into Zend.
- Pass explicit registry/candidate metadata, plugin ZIP, and selected Pass-1
  request artifacts to the standalone Zend CLI/engine. That offline interface is
  allowed to analyze artifacts but must contain no Docker, Compose, HTTP, config
  exporter, or replay dependency.
- Safe ZIP materialization remains per-run temporary extraction; resolve callback
  source only through the verified plugin root.

### 3. Evidence model and parameter merge

- Preserve `InputSignatureExtractor` as a static candidate proposer. It is not
  full taint analysis and static evidence never proves current-run reachability or
  transport placement.
- Normalize per-field evidence to ordered, deduplicated records using only:
  `zend_superglobal_read`, `rest_schema_declared`, `rest_get_param_name_only`,
  `runtime_query_observed`, `runtime_form_body_observed`, `runtime_json_observed`,
  and `legacy_request_recipe`.
- Only `zend_superglobal_read` with a direct `$_GET`/`$_POST` source, runtime
  query/form/JSON observation, or a legacy recipe may set transport location.
  `WP_REST_Request::get_param()` contributes only a name candidate via
  `rest_get_param_name_only`; REST schema declares a candidate but neither schema
  nor HTTP method proves query/body/json placement.
- Merge static candidates, REST `route_common_argument_definitions` plus
  `argument_definitions`, and sanitized runtime observations by field name and
  proven location. Schema-only and name-only REST fields remain
  `unknown`/blocked. `$_REQUEST` stays blocked unless exactly one runtime or
  recipe transport proof resolves it. Do not infer JSON from `php://input` or
  assignment/return/object-property flow not captured by the extractor.
- Redact and block nonce, cookie, authorization, token, password, and secret
  fields. Persist parameter names and evidence only—never submitted values.

### 4. Enriched seeds and legacy config bridge

- Zend writes, under `fuzzer/output/zend-discovery/<legacy-run-id>/`:
  - `seeds/<callback-id>--<method>.json` for each canonical candidate;
  - `zend_enriched_seeds.json` in legacy seed schema;
  - `zend-enrichment-summary.json` with admission/block status;
  - `endpoint-catalog.json` with source-resolution and evidence paths.
- Every individual seed contains `legacy_run_id`, `plugin_slug`, canonical
  candidate identity, `callback_id`, `pass1_request_id`, resolved method,
  parameters, blocked parameters, per-field evidence, and source-resolution
  status. It does not contain a Pass-2 request ID.
- Add a legacy-side adapter that reads raw `suggested_seeds.json` and Zend enriched
  seeds, merges in memory, replaces only the matching canonical candidate, and
  deduplicates by the complete identity above. Raw legacy suggestions remain
  unchanged on disk.
- The adapter sends only `final_fuzz_export_allowed` candidates with nonempty
  fuzzable fields to the existing exporter. It preserves fixed action, bootstrap
  values, auth behavior, headers, route, and resolved method. It must not modify
  config exporter or generated runner semantics. A blocked candidate does not
  prevent independent candidates from reaching Pass 2.

## Tests and acceptance evidence

- Unit-test safe ZIP extraction, canonical identity/dedup, Pass-1 versus Pass-2
  request-ID separation, exact current-run mismatch blocking, and absence of
  Docker/probe/export/replay dependencies in Zend.
- Test evidence semantics: direct static `$_POST` plus body proof → form body;
  REST GET schema plus runtime query proof → query; REST POST schema plus runtime
  body proof → body; schema-only → blocked/unknown; `$_REQUEST` without placement
  proof → blocked; `get_param()` name-only does not establish a location.
- Test security and batch behavior: nonce/cookie/secret values never enter fuzz or
  artifacts; an authenticated `wp_ajax_*` and `admin_post_*` use legacy UOPZ
  admission; a proven zero-fuzz candidate is blocked while other candidates run.
- Test wrapper behavior: generated mode without `-UseZendDiscovery` is unchanged;
  opt-in mode has two passes, a shared `legacy_run_id`, fixed action, distinct
  request IDs, and no public standalone Zend mode.
- Bounded live fixture must prove: Pass 1 reaches the callback, Zend emits a
  nonempty enriched candidate, Pass 2 emits a config and replay artifact for the
  same run/canonical identity, and Pass-2 request ID differs from the Pass-1 ID.
  Report `BLOCKED` or `FAILED` exactly if any required proof is absent; do not
  synthesize artifacts or weaken a gate.

## Boundaries

- No login automation, real cookie/authorization/nonce values, insecure bypasses,
  or weakened correlation gate.
- No changes to the legacy config/replay runner contract beyond passing the new
  opt-in run metadata and temporary Pass-1 inputs.
- No Phase 10–13 artifacts, scripts, or gates are modified or invoked.
