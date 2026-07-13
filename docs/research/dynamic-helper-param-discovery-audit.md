# Dynamic helper parameter discovery audit

Status: planning only. No production code changed. Evidence paths are relative to `phuzz-main/code` unless stated.

## 1. Executive conclusion

Feasible as an opt-in experiment. UOPZ can attach entry hooks to named functions and named class methods; current repository already uses `uopz_set_hook` for named WordPress functions and `WP_Hook` methods. It cannot subscribe to every PHP array-offset read, every comparison, or every helper call without first enumerating and hooking symbols. `uopz_set_return` is unsuitable: it changes behaviour.

Recommended prototype: **source-assisted, runtime-guided helper discovery**. Static analysis first classifies a symbol as `request_reader`, `trace_only`, or `unsupported`; only a `request_reader` can turn an observed argument into parameter evidence. UOPZ records evaluated arguments only for readers and uses trace-only symbols only for call-chain context. Emit independent experimental configs; do not merge baseline outputs in v1.

UOPZ smoke test completed in the repository web container: PHP 8.2.10, uopz loaded. Namespaced functions; instance, static, inherited, private and protected methods; hook-after-definition; late symbols; duplicate installation; debug backtrace; unchanged return; and real `cfx_form::post('cfx_settings')` argument capture all passed. Full isolated test: `fuzzer/tests/experimental/uopz_capability_smoke.php`.

## 2. Current end-to-end pipeline

| Stage | file:function (lines) | input | output |
|---|---|---|---|
| PHP bootstrap | `web/instrumentation/__fuzzer__startcov.php:3-5`; `hook_coverage/bootstrap/load_uopz_hook_coverage.php:25-45`; `uopz_mu_plugin.php:9-24` | `FUZZER_ENABLE_UOPZ=1`, auto-prepend / MU plugin | loads `uopz_hook_runtime.php`, re-installs after WP milestones |
| instrumentation startup | `uopz_hook_wp.php:21-74, 1063-1241` | request globals, WP symbols | `$GLOBALS['__uopz_request']`; hooks `add_*`, REST registration, `WP_Hook`, `call_user_func*` |
| registration capture | `uopz_hook_wp.php:592-687,1080-1127` | hook name, callback, priority, accepted args | `hook_coverage.registered_callbacks[callback_id]` |
| callback origin | `uopz_hook_wp.php:1495-1668` | callback object/string | reflection metadata: `source_file`, `source_line`, formal params, target flag; no `end_line` emitted |
| execution capture | `uopz_hook_wp.php:797-1006,1183-1237` | WP_Hook snapshot and call-user-func callbacks | `executed_callbacks`; existing callback stack pushed only around observed callback dispatch |
| request/aggregate artifact | `uopz_hook_wp.php:1275-1474` | request state | `/shared-tmpfs/hook-coverage/requests/<request_id>.json`, `total_coverage.json`; request id generated at `:29-48` |
| entrypoint classification | `fuzzer/hook_energy/entry_classifier.py` (`classify_callbacks`, inspect by test contract `tests/test_entry_classifier.py:82-270`); templates `entrypoints.py` | registered/executed callback metadata | classified callback rows + HTTP seed templates |
| source mapping + static extraction | `seed_generation/source_resolver.py:40-88`; `input_extractor.py:64-93,95-125,129-192` | callback source file/start/end (end inferred) | `input_params`: name/source/location/confidence/evidence/line |
| seed model/report | `seed_generation/generator.py:31-106,112-178,257-328` | total coverage + extraction | `hook_gap_report.json`, `suggested_seeds.json/.md`; seed has body/query and `input_params` |
| config export | `config_exporter.py:16-79,82-134` | `suggested_seeds.json` | `fuzzer/configs/generated-config/<plugin>/*.json`, `generated_config_summary.json` |
| parameter summary | `config_exporter.py:137-192` | generated config + seed report | `generated_param_summary.json`; status `fuzzing_ready`, `entrypoint_only`, `manual_analysis` |
| replay | `generated_config_runner.py:81-191,239-281`; runner wiring `scripts/wordpress/run-wordpress-phuzz.ps1:256-275` | generated summary + each config | `generated_config_run_summary.json`, per-run request artifacts |
| validation | `seed_validator.py:272-396`; runner uses it at `generated_config_runner.py:148-165` | expected callback metadata + new request JSON | `validation_result.json`; `callback_reached` iff callback id/repr in executed callbacks |
| PowerShell/env propagation | `scripts/wordpress/run-wordpress-phuzz.ps1:1-15,51-70,191-210`; `docker-compose.yml:37-81`; `fuzzer/scoring.env:1-31` | PS params -> temporary Compose override -> container environment -> Python CLI | `FUZZER_CONFIG`, target plugin/path; scoring mode already env-file based |

Flow: `add_action/add_filter/register_rest_route` -> request JSON/`total_coverage.json` -> `LiveHookSeedGenerator` -> `InputSignatureExtractor` -> suggested seed -> `config_exporter` -> generated PHUZZ JSON -> `generated_config_runner` -> `seed_validator.evaluate_artifact_payloads` -> validation artifact.

## 3. Existing UOPZ capability matrix

| Question | Result | evidence / limit |
|---|---|---|
| Every plugin helper now? | No | install list is fixed at `uopz_hook_wp.php:1080-1237`; no symbol inventory |
| Predefined allowlist now? | Yes | WP registration/dispatch and `call_user_func*` only |
| Install after registration? | Not implemented; technically layer supports named hook installation | `__uopz_try_hook_function/method:1031-1060`; callbacks are reflected at registration but not hooked |
| Namespaced functions | Not demonstrated locally | use fully-qualified reflected name in prototype smoke test; current code only strings common WP globals |
| Instance/static methods | Yes for named known methods | `uopz_set_hook($class,$method,$closure)` at `:1047-1056`; `WP_Hook` proof `:1183-1215` |
| Arguments without replacement | Yes, entry-hook args in current callbacks | variadic captures at `:1080-1237`; original dispatch continues |
| Return values without behaviour change | No current mechanism | `uopz_set_hook` is entry-only here; `uopz_set_return` present only in override files and changes returns |
| Core/plugin/vendor classification | Plugin-target only, path-based | `__uopz_path_matches_target:163-183`; reflection target flag `:1614-1655`; no separate vendor class |
| Associate helper with entrypoint/request | Partially | request id global `:41-48`; callback stack `:457-473,968-1006`; helper calls not tracked |
| Internal functions | request-reader hooks possible only for specific names; no source location | reflection explicitly notes internal/dynamic callback unresolved `:1649-1655` |
| Closures | callback metadata works, generic helper inventory/identity needs separate policy | Reflection handles closures `:273-282,1534-1535`; no current hooks |
| Already executing functions | No retroactive entry observation | hooks are installed before invocation; current install has one-shot guard `:1063-1067` |

## 4. HTTP-reader coverage now

| Pattern | Static now | Dynamic now | prototype need |
|---|---|---|---|
| `$_GET/POST/REQUEST/COOKIE/FILES['x']`, including literal nested keys | Yes | No | userland symbol hooks plus source-assisted superglobal-read attribution; UOPZ alone cannot see array offset |
| `php://input` + `json_decode` then literal array key | Yes | No | hook reader functions or source-assisted parse |
| `filter_input(INPUT_GET/POST/COOKIE,'x')` | Yes | No | hook `filter_input`; args disclose name/source |
| `filter_input_array` | No | No | hook plus inspect returned array cannot identify consumed individual key reliably |
| `wp_unslash`, `sanitize_text_field`, `sanitize_key`, `absint`, `intval` around direct superglobal | Direct inner literal read is Yes | No | no hook needed for direct extraction; helper-only case needs target hooks + source assist |
| `WP_REST_Request::get_param/get_params/get_query_params/get_body_params/get_json_params`, ArrayAccess | No | No | named method hooks; `get_param` arg high confidence, bulk/ArrayAccess lower confidence |
| custom wrappers | Only shortcode-default special case (`input_extractor.py:129-162`) | No | target symbol hooks + lightweight source inspection |

## 5. Pattern feasibility

| Pattern | observable event/name source | UOPZ enough? | emitted evidence/confidence |
|---|---|---|---|
| A `request_value('mode')->$_POST[$name]` | helper entry arg `mode`; helper source proves POST | No: hook sees arg, not offset | custom_helper, POST, helper call chain, high |
| B sanitizer wrapper | same as A; sanitizer irrelevant | No | high; reader function wrapper, source location at helper read |
| C computed `$name` | helper entry; no direct name unless hook `calculate_parameter_name` return (unsafe/absent) or source runtime tracing | No | `parameter_name=null`, POST known only if source proves it; low |
| D `$request->get_param('mode')` | method arg | Yes for name/source after dedicated method hook | REST parameter, medium/high; source category from REST request method should be `REST_COMBINED` |
| E deep chain | hooks on each target symbol record stack; helper arg supplies key | Not by itself: all chain symbols need hooks | chain callback/build_profile/request_value, high |
| F concatenated key | helper entry receives evaluated `mode` | Yes for name, source needs helper source | high |

## 6. Scope options and recommendation

| option | PHP8/current image feasibility | overhead/risk | name capture | per request | prototype |
|---|---|---|---|---|---|
| A all target-plugin symbols after bootstrap, gated | feasible design; PHP 8 image + UOPZ enabled (`web/Dockerfile:1,27`, `php.ini:6`) | medium/high; install failures and recursion guard required | high for literal/dynamic helper args | yes, env read at request start | **Yes, constrained** |
| B callbacks then recursively helpers | not possible with UOPZ alone: no first-call observer to discover unhooked helper | lower if possible | incomplete | yes | no |
| C known reader helpers only | feasible | low | high for filter/REST, misses wrappers | yes | no |
| D Xdebug function trace | Xdebug installed but mode is coverage (`php.ini:10-11`) | high trace volume; config change | args may be available, superglobal offset not guaranteed | yes | no |
| E UOPZ identity + Xdebug trace | possible future | highest complexity | good call chain, weak array offset | yes | no |
| F Zend opcode instrumentation | not exposed by repo | very high/extension work | can see array dims/comparisons | theoretically | no |

Guardrails: inventory reflected user-defined symbols in `FUZZER_COVERAGE_PATH`; exclude instrumentation and vendor by default; maximum symbols/request; do not hook `uopz_*`; callbacks only arm collection; stack guard blocks collector recursion. Validate namespaced, static, instance, closure and internal behaviour in a clean PHP-container smoke test before claiming support.

## 7. Artifact and merge design

Extend each existing request artifact, not `total_coverage.json`: add `runtime_param_discoveries` to `/shared-tmpfs/hook-coverage/requests/<request_id>.json`. Per-request preserves request/callback correlation; Python writes aggregate `dynamic_param_discoveries.json` in a new experimental output root.

```json
{
  "schema_version": "hookphuzz-runtime-param-v1",
  "request_id": "same-as-request-artifact",
  "entrypoint_type": "wp_ajax",
  "entrypoint_name": "wp_ajax_save_profile",
  "callback_id": "sha1-id",
  "callback_repr": "Plugin::save_profile",
  "parameter_name": "mode",
  "parameter_path": ["mode"],
  "http_source": "POST",
  "observed_value": null,
  "value_state": "redacted",
  "reader_type": "custom_helper",
  "reader_function": "request_value",
  "reader_file": "/var/www/html/wp-content/plugins/p/includes/request.php",
  "reader_line": 123,
  "call_chain": ["Plugin::save_profile", "build_profile", "request_value"],
  "confidence": "high",
  "discovery_mode": "dynamic-helper"
}
```

Use `X-Fuzzer-Covid` already sent by `seed_validator.py:61-63`; it is not currently copied into the PHP request id, so add an explicit `correlation_id` from that header rather than pretending equality. Deduplicate aggregate rows by `(callback_id,http_source,parameter_path,reader_file,reader_line)`; retain all call chains/provenance. Store no values by default; allow only type/empty/presence (`value_state`), redact names matching `pass|token|secret|key|cookie|nonce` unless an explicit debug switch exists. Parameter name is evidence; candidate seed remains a later field (`candidate_seed`, unset in v1).

V1 merge: `static` unchanged. `dynamic-helper` generates independent configs only. `hybrid` is planned: union keyed by normalized `(source,path)`, static+dynamic provenance array, static source wins routing only when dynamic source unknown. Same name GET/POST stays two parameters. Empty observation is usable name evidence, not a seed. `action`, route and nonce remain fixed unless existing model explicitly fuzzes them. Preserve bracket paths (`settings[mode]`, `filters[0][name]`) and map JSON/REST into explicit `BODY_JSON`/REST sections; do not flatten ambiguously.

## 8. Iterative replay

```
baseline bootstrap config -> replay -> require callback_reached
  -> collect/dedupe high-confidence discoveries -> expand experimental config
  -> hash canonical config -> replay next iteration
  -> stop on no new discovery, repeated hash, failed/timeout, or limit
```

Defaults proposed: 2 discovery iterations per entrypoint, 64 target symbols, 32 discoveries, 8 configs, 30-second replay timeout. Failed/not-reached callback contributes no trusted parameter evidence. `discovery_depth` is replay generations; PHP call-stack depth is collector chain truncation (e.g. 16); recursive child-hook depth is existing hook-registration nesting; fuzzer mutation iteration is PHUZZ’s own loop. They are independent. Reuse only recursive mode’s cleanup/duplicate/timeout patterns (`phuzz.ps1:291-304,328-424`), not its depth meaning.

## 9. Minimal integration map

| file | layer/change | reason |
|---|---|---|
| `web/instrumentation/hook_coverage/uopz_hook_wp.php:41-74,968-1006,1031-1060,1446-1474` | modify: mode gate, reflected target symbol hook installation, `RuntimeParamCollector` calls, request extension | sole runtime/request/callback-stack boundary |
| `web/instrumentation/hook_coverage/runtime_param_collector.php` | new PHP file | keep collector, hook/stack/serialization separate from WP registration code |
| `fuzzer/hook_energy/seed_generation/dynamic_param_artifacts.py` | new | parse, validate, redact-aware aggregate/dedupe request discoveries |
| `fuzzer/hook_energy/seed_generation/dynamic_param_merger.py` | new | deterministic static/dynamic merge; avoids changing regex extractor semantics |
| `fuzzer/hook_energy/seed_generation/config_exporter.py:82-192` | modify | export experimental config set and summary metadata using existing config writer |
| `fuzzer/hook_energy/seed_generation/dynamic_config_replay.py` | new | bounded iterative coordinator over existing runner API |
| `scripts/wordpress/run-wordpress-phuzz.ps1:1-15,51-70,109-210,256-275` | modify | validation, Compose env propagation, distinct paths, bounded CLI sequence |
| `docker-compose.yml:41-48` | no base change required | temporary runner override already passes web env; preserve default |
| tests listed below | new fixtures/tests | mode isolation and exact evidence contracts |

## 10. Mode isolation

Use PowerShell naming consistent with existing `-Mode` and hyphenated runner directories:

`./scripts/wordpress/run-wordpress-phuzz.ps1 -PluginSlug crm-perks-forms -RunGeneratedConfigs -ParamDiscoveryMode dynamic-helper`

Parameter: `[ValidateSet('static','dynamic-helper','hybrid')] [string]$ParamDiscoveryMode = 'static'`. Pass `HOOKPHUZZ_PARAM_DISCOVERY_MODE=$ParamDiscoveryMode` in `New-PluginOverrideFile`. `static` must not add PHP hooks, JSON keys, directories, or alter command inputs. Invalid values fail PowerShell validation; PHP treats unknown/missing as `static` and records no discovery. Experimental roots: `fuzzer/output/param-discovery/<plugin>/<mode>/` and `fuzzer/configs/generated-param-discovery/<plugin>/<mode>/`; metadata includes mode/schema/limits/baseline summary path.

## 11. Concrete test plan

| fixture/test | expected request evidence | generated behavior |
|---|---|---|
| direct `$_POST['direct_param']` | static row POST/direct_param; dynamic mode may record only if source-assisted collector enabled | static baseline unchanged; hybrid one fuzz selector |
| `request_value('helper_param')` | helper + POST + literal arg + chain | dynamic config contains body `helper_param` |
| callback->service->helper deep_param | three-item chain | one dynamic selector, chain retained |
| REST `get_param('rest_param')` | REST reader method/arg | REST config param with explicit source metadata |
| `request_value('mo'.'de')` | evaluated `mode` | dynamic selector `mode` |
| duplicate static+dynamic | two provenance records one normalized param | hybrid one selector |
| GET+POST same name | two source rows | two sections/selectors |
| `$_POST['settings']['mode']` | path `[settings,mode]` | bracket-path body param |
| no-new fixed point | iteration two adds zero | status `fixed_point`, no third replay |
| iteration/depth limit | limit metadata/reason | no config past cap |
| disabled feature | no new PHP/request/summary/config output | byte-for-byte baseline fixture output |
| callback not reached | discoveries tagged untrusted/discarded | no expansion |

Use unit fixtures for merger/exporter and an integration plugin fixture for runtime UOPZ. Add container smoke tests for namespaced function, instance/static method, closure, internal function, and hook installation error handling.

## 12. Validation target

Recommend existing `crm-perks-forms`, conditional on fresh replay confirmation. It is locally present and runner accepts local ZIP/config pairing. Evidence:

`includes/admin-pages.php:18` registers `wp_ajax_vx_form_save_api_settings` -> `cfx_admin::save_api_settings` at `:723`; that callback calls `cfx_form::post('cfx_settings')` at `:731`; helper `crm-perks-forms.php:887-892` reads `$_REQUEST[$key]` and sanitizes through `clean()` (`:900-905`). This is precisely helper argument -> dynamic superglobal key. Existing historical artifacts may be stale; run fresh generated replay and require `callback_reached` before using it. If setup/auth prevents it, create a minimal local test plugin instead.

## 13. Future BranchSeedExtractor

Insert after `DynamicParamMerger`, before config expansion:

`BranchSeedExtractor.extract(parameter_evidence, executed_call_chain, source_locations) -> list[BranchSeedEvidence]`.

Dynamic input: reached callback, parameter names/source, runtime call chain. Source-assisted input: helper/callback source slices, comparisons/switch cases/in-array literals tied to the known parameter/path. Output candidate values carry source location/confidence, then `DynamicConfigExpander` can choose them. UOPZ function hooks cannot see PHP comparison opcodes or branch operands; they see only named function/method entry, hence cannot directly observe every expression.

## Risks and open questions

- UOPZ signature behaviour for namespaced symbols, closures, inherited/static methods must be smoke-tested in the pinned container; no local container was running.
- UOPZ cannot observe arbitrary superglobal array reads. The prototype’s source-assisted helper-read classification is required for HTTP source; hook args alone only prove a helper received a value.
- Enumerating target symbols can alter timing/error paths and add overhead. Bound it, gate it, and retain install failures in debug metadata.
- `$_REQUEST` precedence, JSON decoding conventions, REST parameter precedence, and PHUZZ support for bracket/JSON selectors need explicit canonical rules before expansion.
- Existing request id is random and not header-derived; add correlation id, do not change baseline id format.
- Secrets must be name-redacted and values omitted by default.

## Commands executed

- `rg` inventory of instrumentation, pipeline, runners, modes, and plugin source: completed.
- bounded repository source reads: completed.
- `docker compose ps`: completed; no containers.
- official PHP manual fetch attempted: timed out and was terminated; not used as evidence.
- no tests run; no generated artifacts created.

## 14. Corrected helper-reader proof model

This is source-assisted, runtime-guided discovery, not fully dynamic parameter discovery. A call such as `request_value("mode")` proves only a string argument. It becomes HTTP parameter evidence only after `HelperRequestReaderAnalyzer` proves that the corresponding formal argument is an index/key consumed by a supported request source.

`InputSignatureExtractor` cannot prove that mapping. Its superglobal regex accepts only quoted keys (`input_extractor.py:13-18`), its filter regex only quoted names (`:19-22`), and it does not parse formals or bind variables. For `function post($key) { return $_REQUEST[$key]; }`, it emits nothing and cannot map `$key` to argument 0.

### HelperRequestReaderAnalyzer contract

Input: reflected target-plugin function/method plus resolved source file. Output is either one or more mappings or a classification:

```json
{
  "symbol": "cfx_form::post",
  "role": "request_reader",
  "parameter_argument_index": 0,
  "formal_parameter": "key",
  "http_source": "REQUEST",
  "evidence": {"expression": "$_REQUEST[$key]", "file": "...", "line": 891},
  "confidence": "high"
}
```

Roles: `request_reader` (mapping proven); `trace_only` (target symbol suitable only for call chain); `unsupported` (no supported mapping). Runtime evidence is `(reader mapping, actual argument, active callback/request, call chain)`. Candidate seed is later config-expansion data; it is never equal to arbitrary runtime argument evidence.

Prototype parser choice: PHP tokenizer (`token_get_all`) in a new small Python-compatible analyzer is not available because Python cannot invoke PHP's tokenizer directly. Smallest reliable repository option is a dedicated PHP tokenizer CLI/JSON bridge, called by Python; it supports only exact syntactic patterns and formal-variable equality. Regex/source windows are insufficient; `nikic/php-parser` is not present; runtime-only UOPZ cannot observe array offsets. Do not add an AST dependency for Phase 2.

Supported analyzer patterns: `$_GET[$arg]`, `$_POST[$arg]`, `$_REQUEST[$arg]`, `$_COOKIE[$arg]`, `filter_input(INPUT_GET|POST|COOKIE, $arg)`, `WP_REST_Request::get_param($arg)`. No arbitrary dataflow.

V1 classification: named functions/methods after inventory including namespace/instance/static/inherited/private/protected are smoke-tested supported; trace-only only when a reflected target symbol is safely hookable. Closures, magic `__call`, arbitrary `ArrayAccess`, late-defined symbols after inventory, direct opcode-level array reads, `filter_input_array`, computed keys, bulk REST getters, and arbitrary dataflow are deferred/unsupported. Late-defined symbols can be hooked after definition but are not automatically discovered by a one-time inventory.

### Revised modes

- `static`: existing behavior unchanged.
- `dynamic-helper`: only parameters proven through `request_reader` mappings; direct superglobal reads excluded unless processed by the helper analyzer.
- `hybrid`: current static extraction plus proven dynamic helper evidence.

### Phases

0. UOPZ capability smoke test only. Completed successfully.
1. Manual reader mapping only: `cfx_form::post`, argument 0, `REQUEST`; emit runtime evidence only; no config expansion.
2. Implement `HelperRequestReaderAnalyzer`; reproduce Phase 1 mapping automatically.
3. Produce one independent experimental config from trusted runtime evidence and replay once.
4. Add bounded iterative discovery/replay.

### Smoke command and result

`docker compose up -d web --build`; then `docker compose cp fuzzer/tests/experimental/uopz_capability_smoke.php web:/tmp/uopz_capability_smoke.php`; then `docker compose exec -T web php -d auto_prepend_file= /tmp/uopz_capability_smoke.php`.

All required checks passed. Duplicate `uopz_set_hook` replaced the earlier hook (`effect_count=10`); original return stayed `duplicate`. `cfx_form::post('cfx_settings')` hook captured `["cfx_settings"]` and returned `settings-value`; no `uopz_set_return` used.

Phase 1 only changes: new `web/instrumentation/hook_coverage/runtime_param_collector.php`; minimal gated calls/config in `uopz_hook_wp.php`; new `fuzzer/tests/experimental` runtime fixture/test; no `InputSignatureExtractor`, generator, exporter, config, or PowerShell change. Phase 1 tests: disabled mode emits no discovery; active callback plus `cfx_form::post` emits REQUEST/key/callback/request/call chain; arbitrary trace-only string argument emits none; return unchanged; callback-not-reached evidence discarded; dedupe repeated helper reads.