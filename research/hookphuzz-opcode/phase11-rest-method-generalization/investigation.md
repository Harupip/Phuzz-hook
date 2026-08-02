# Phase 11 REST Method Generalization — Investigation

## Scope and current code path

`register_rest_route()` is intercepted by the UOPZ instrumentation in
`phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php:1129-1138`.
The interceptor calls `__uopz_register_rest_route()` (`:770-796`), which records
one `registered_callbacks` entry per endpoint callback.  It records
`entrypoint_type=rest_route`, `namespace`, `route`, a normalized `methods` list,
and the permission callback (`:787-795`).  The registered entry is later consumed
by `LiveHookSeedGenerator`; REST callbacks are recognized and routed to
`seed_template_for_callback()` / `rest_seed_template()` in
`phuzz-main/code/fuzzer/hook_energy/entrypoints.py:138-185`.

`rest_http_template()` derives `/wp-json/<namespace>/<route>` from metadata
(`entrypoints.py:188-205`).  `resolve_http_methods()` produces one seed decision
per declared method (`method_resolution.py:19-50`).  The generator carries that
decision through to suggested seed variants, then
`build_config_for_seed_item()` writes PHUZZ JSON (`seed_generation/config_exporter.py:16-71`).
The batch runner invokes the existing fuzzer container and validates fresh
instrumentation request artifacts by callback identity
(`seed_generation/generated_config_runner.py:94-188`).

## Current method schema and precedence

The current provenance fields are `resolved_method`, `candidate_methods`,
`method_status`, `method_source`, `method_confidence`, `method_evidence`,
`observed_request_method`, and `route_declared_methods`
(`entrypoints.py:242-251`; `generated_config_runner.py:25-34`).
`resolve_http_methods()` currently applies precedence in this order:

1. `route_declared_methods` (`method_resolution.py:38-50`);
2. source-exact `$_GET` / `$_POST` evidence (`:52-65`);
3. request-ID/callback/plugin-correlated runtime observation (`:67-84`);
4. an ambiguous record (`:86-102`).

`correlated_runtime_observation()` does require callback identity, request ID
when supplied, target plugin, and a valid method (`:133-169`).  However, a
declared route is returned before the correlated observation is checked for
membership in the declared method set.  Thus declared `GET` plus correlated
observed `POST` currently resolves to GET instead of `conflict`.

`normalize_http_methods()` uppercases, trims, splits comma/pipe separators,
flattens sequences and mapping shapes, and preserves first-seen order
(`method_resolution.py:105-130`).  It silently drops invalid tokens.  It also
contains a Python hard-coded map for WP REST constants (`:10-16`), whereas Phase
11 must capture actual constant values from the running WordPress version for
its runtime artifact.

## Current gaps requiring changes

* The PHP instrumentation defaults missing endpoint methods to `GET` twice:
  `__uopz_normalize_rest_methods()` creates `[$methods ?: 'GET']` and returns
  `['GET']` if empty (`uopz_hook_wp.php:730-744`); registration also passes a
  fallback `'GET'` (`:791-792`).  This violates the no-runnable-fallback rule.
* The Python ambiguous record exposes `candidate_methods=["GET", "POST"]`
  despite having no exact evidence (`method_resolution.py:86-101`).  Export is
  blocked today by `SeedConfigSkip` (`config_exporter.py:29-30`), but the
  evidence schema misleadingly presents defaults as candidates.
* Multiple route methods are immediately expanded to separate `resolved`
  records (`method_resolution.py:40-50`) and `rest_seed_template()` picks the
  first decision (`entrypoints.py:170-177`).  The original entrypoint has no
  explicit `resolved_multiple` representation or parent/variant linkage.
* `rest_http_template()` also stores the first method as its template method
  (`entrypoints.py:203-205`); this is a deterministic but undocumented choice.
* Regex routes are concatenated unchanged into `/wp-json/...`; no materializer
  exists (`entrypoints.py:188-205`).  A route such as `(?P<id>\\d+)` would
  produce a non-runnable URL.
* The generic config exporter preserves a list in `methods` (`config_exporter.py:32-42`),
  but does not provide a per-method execution variant for multi-method REST
  entries.  The PHUZZ runtime's body encoding is outside this Python exporter;
  the current validation helper only proves form-style `data` preservation for
  PUT/PATCH/DELETE (`tests/test_seed_method_inference.py:306-381`), not JSON
  encoding or the actual PHUZZ request preparation.

## Existing runner and correlation behavior

`generated_config_runner.py` controls Docker execution, snapshots
`/shared-tmpfs/hook-coverage/requests` before every config, then validates only
new artifacts by hook/callback (`:106-188`).  This protects against stale
artifacts at the file-set boundary, but its validation result does not itself
require a particular request ID or request method.

The WordPress instrumentation stores `request_id`, `http_method`, and
`target_plugin` on executed callbacks (`uopz_hook_wp.php:846-850`).  For REST
path matching it reads `rest_route` or `/wp-json/` path
(`uopz_hook_wp.php:854-866`).  Phase 11 must add its own same-request gate to
prove callback/marker/request-ID/method rather than relying on HTTP status or
generic callback coverage.

## WordPress REST constants

The vendored WordPress runtime declares `READABLE='GET'`, `CREATABLE='POST'`,
`EDITABLE='POST, PUT, PATCH'`, `DELETABLE='DELETE'`, and
`ALLMETHODS='GET, POST, PUT, PATCH, DELETE'` in
`phuzz-main/code/web/applications/wordpress/wp-includes/rest-api/class-wp-rest-server.php:24-56`.
These source values are investigation evidence only; Phase 11 will query the
loaded class at runtime and emit the result as the authoritative artifact.

## Phase 9 and Phase 10 context

Phase 9 remains an isolated replay-validation baseline; its test suite is
under `research/hookphuzz-opcode/phase9/tests/`.  Phase 10's CF7 REST lab is
also isolated and currently documents `PHASE_10_CF7_REST_FAIL` because
authentication blocked callback/runtime proof
(`research/hookphuzz-opcode/phase10-cf7-rest/README.md:15-24`).  Its request
script uses only `curl -G` (GET) (`wordpress/rest-request.sh:15-19`) and its
generated config hard-codes `methods=["GET"]`
(`collector/generate_config.py:44-57`); it is not a method-generalization
implementation and will be treated only as a regression target.

## Required Phase 11 changes

1. Make method normalization and resolution fail closed: no empty-method GET
   default, invalid-evidence warnings, `ambiguous` with no runnable method,
   and `conflict` whenever exact correlated evidence does not intersect route
   declaration.
2. Preserve a multi-method parent entrypoint and create deterministic one-method
   replay variants with parent linkage.
3. Materialize the bounded named numeric route pattern before export; block
   unsupported regexes.
4. Build a self-contained Docker fixture and runner that records independent
   callback-side JSON evidence, actual prepared/sent method, JSON bodies, and
   same-request IDs.
