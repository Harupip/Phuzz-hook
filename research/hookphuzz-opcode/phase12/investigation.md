# Phase 12 investigation

## Current flow (before Phase 12 changes)

`register_rest_route()` is observed by the UOPZ hook installed in
`phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php:1135-1144`.
It calls `__uopz_register_rest_route()` (`:776-802`).  That function reduces a
single definition or numeric endpoint definitions with
`__uopz_rest_endpoint_args()` (`:752-774`), filters to target callbacks, and
writes namespace, route, normalized methods, callback identity, and permission
callback to `registered_callbacks` (`:793-800`).  It does **not** retain
`args`, an endpoint index, common arguments, or registration provenance.

The method normalizer (`uopz_hook_wp.php:730-750`) flattens nested method
declarations and comma/pipe-separated strings.  The endpoint reducer treats a
top-level `callback` as one endpoint and otherwise only accepts numeric entries
having a callback (`:758-770`).  Thus invalid endpoint entries and top-level
common `args` are silently dropped.  Named groups are not interpreted here.

`phuzz-main/code/fuzzer/hook_energy/rest_routes.py:7-50` materializes only
named `\\d+` groups; it produces `/items/1` with substitution evidence and
blocks all other route regexes.  It does not identify parameter transport.

The generated-config path is `seed_generation/config_exporter.py:16-85`.
It exports `body`, `query_params`, `headers`, and `cookies` only (`:53-72`) and
converts every section value to `str` (`:223-237`).  There is no path-value or
JSON-body representation.  The runtime request builder does support JSON when
`Content-Type` is `application/json`, but receives the already stringified body
map (`phuzz-main/code/fuzzer/fuzzer.py:496-547`, especially `:525-540`).
Consequently JSON primitive types are lossy today.  `phuzz_config_writer.py`
also guesses a body versus query placeholder from HTTP method (`:44-52`), which
is unsafe for schema-only REST parameters and is not used for Phase 12 export.

Request IDs are preserved by the existing runner as
`X-HookPhuzz-Request-ID` (`fuzzer.py:507-510`).  Phase 11B uses a fresh UUID,
writes one callback artifact per ID atomically, and checks callback, marker,
method, and request ID (`phase11b-cf7/scripts/run_phase11b.py:120-184`).  Its
observer only hooks `WP_REST_Request::get_param` for `search`
(`hookphuzz-phase11b-cf7-observer.php:77-99`); none of the parameter collection
readers (`get_url_params`, `get_query_params`, `get_body_params`,
`get_json_params`, or `get_file_params`) are observed.

## Missing information and risks

The recorder currently loses the registered argument schemas, endpoint index,
common-argument merge context, callback forms in schema callbacks, and all
parameter transport/runtime evidence.  The config exporter cannot encode a
path value nor distinguish form and JSON bodies, and stringification would turn
JSON `true`, `1`, and `1.0` into strings.  HTTP 200 alone is insufficient: the
existing reliable gate is callback/parameter/request-ID correlation.

## Reusable components and modification points

Phase 12 can reuse the target-callback registration hook, callback identity
helpers, REST route materializer, current authenticated CF7 login/nonce flow,
the generated config shape, and Phase 11B's atomic callback artifacts.  The
minimal shared change is to retain a safe, deterministic argument capture on
the existing registered REST entry.  Phase 12 normalization, seed selection,
transport preparation, and fixture observation belong in the isolated
`research/hookphuzz-opcode/phase12` harness.

Regression risk is confined to registration artifacts: existing consumers must
continue to receive the current namespace/route/method/callback fields and no
object state, cookies, nonce, or authorization data may enter artifacts.

## Phase 12 closure investigation

The Phase 12 implementation is in `fixture-plugin/hookphuzz-phase12.php:1-29`,
`scripts/phase12_schema.py:1-93`, and `scripts/run_fixture.py:1-99`. The fixture
currently registers path/query (`/items/(?P<id>\\d+)`), JSON (`/json`), form
(`/form`), runtime-only (`/runtime`), and PUT/PATCH (`/methods`) routes. Its
shared schema exercises required, optional/default, enum, integer, number,
boolean, array, object, validation, sanitization, unsupported pattern/object,
and declared-unread fields. It does not yet exercise every requested negative
correlation or explicit schema/runtime-conflict case.

The exporter writes the PHUZZ config in
`hook_energy/seed_generation/config_exporter.py:16-85`. The real loader is
`Fuzzer.load_config()` (`fuzzer.py:337-352`), candidate creation is
`generate_initial_candidates()` (`:375-449`), and the production request path
is `Fuzzer.prepare_request()` (`:503-554`). Before closure, the fixture runner
called `requests.request()` directly (`run_fixture.py:35-43`), bypassing these
components. The closure runner now loads the exact exported file with
`Fuzzer.load_config`, generates its candidate, and invokes
`Fuzzer.prepare_request` (`run_fixture.py:60-78`). This exposed the loader's
set-based value storage: arrays and objects are unhashable. The compatible
fix retains ordinary behavior while using ordered de-duplicated lists in
`fuzzer.py:267-333`.

The complete runners remain `research/hookphuzz-opcode/phase9/run.sh`,
`research/hookphuzz-opcode/phase10/tests`, and
`research/hookphuzz-opcode/phase11-rest-method-generalization/run.sh`.
