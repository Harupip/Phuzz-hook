# Generated Entrypoint Audit - 2026-08-24

Scope: current source, focused tests, generated-config artifacts, and available runtime callback evidence for WordPress entrypoints.

Interpretation: `direct_http_candidate` means the hook can be mapped to an HTTP template. It does not by itself mean that a PHUZZ config was generated or that the callback was reached. A generated config is `fuzzing_ready` only when the HTTP method and at least one fuzzable parameter are resolved; otherwise it may be `replay_only` or be skipped.

| Entrypoint type | Runtime capture / classification | Generated config | Callback proof | Current status and gap |
| --- | --- | --- | --- | --- |
| `wp_ajax_*` | Yes. Maps to `POST /wp-admin/admin-ajax.php` with fixed `action`. | Yes. Live seed generator, exporter, and generated-config runner support it. | Yes. Real-plugin and generated-config artifacts contain `callback_reached`. | **Supported and proven.** Auth, nonce, parameter provenance, and method evidence remain plugin-specific gates. |
| `wp_ajax_nopriv_*` | Yes. Longer nopriv prefix is matched before authenticated AJAX and maps to the same endpoint. | Yes, with `auth_mode=unauth-capable`. | Yes for runtime AJAX coverage; individual runs may be `expected_auth_skip` or `registered_not_executed` when the target requires the authenticated counterpart. | **Supported and proven as a family.** Do not treat every nopriv row as a failure. |
| `admin_post_*` | Yes. Bootstrap probes include `/wp-admin/admin-post.php?action=hookphuzz_probe`; normal hook registrations are classified. | Yes when method evidence is resolved. | Runner path exists, but the current LearnPress artifact has `ambiguous_http_method`, `config_path=null`, and no callback proof. | **Supported conditionally; current artifact is blocked at method evidence**, not endpoint mapping. |
| `admin_post_nopriv_*` | Yes. Same registration/classification path as authenticated admin-post. | Yes when method evidence is resolved, with `auth_mode=unauth-capable`. | Same conditional runner path; current LearnPress rows are skipped for ambiguous method. | **Supported conditionally; runtime proof still needs a resolved method and reachable branch.** |
| `register_rest_route($namespace, $route, ...)` | Yes. UOPZ records namespace, route, methods, callback, permission callback, and REST metadata. | Yes. Maps to `/wp-json/<namespace>/<route>` and preserves REST metadata without `action`. | Yes. Generated-config and Zend artifacts contain REST `callback_reached` rows. | **Supported and proven.** Bounded numeric route placeholders can be materialized; unsupported regex and schema-only parameters remain blocked/probe-only. |
| `login_form_*` | Partial. Prefix is classified and maps to `/wp-login.php?action=<action>`; bootstrap only exercises selected login actions, not every plugin action. | Yes in the current generator/exporter when method/parameter evidence is available. | No current generated-config/runtime callback proof for this family. | **Code-supported, not runtime-proven.** Needs an action-aware login probe and a real generated-config replay. |
| `admin_action_*` | Yes for direct HTTP classification: maps to `/wp-admin/admin.php?action=<action>`. | **No.** `entrypoints.py` has the mapping, but the live generator allowlist does not include `admin_action_*`. | No generated-config proof. | **Classification-only gap.** Add generator/config support before calling this supported. |
| `heartbeat_received` | Partial. Exact hook maps to `/wp-admin/admin-ajax.php?action=heartbeat`; the default bootstrap probes do not send a heartbeat request. | Yes in the current generator with a fixed probe body (`action`, `_nonce`, `screen_id`, and probe data); method evidence is still required. | No current generated-config/runtime callback proof. | **Code-supported, not runtime-proven.** Needs a real authenticated heartbeat request and valid nonce/context. |
| `heartbeat_nopriv_received` | Partial. Same exact endpoint/action mapping with unauthenticated auth mode; default probes do not exercise it. | Yes in the current generator with `auth_mode=unauth-capable`. | No current generated-config/runtime callback proof. | **Code-supported, not runtime-proven.** Needs a public heartbeat replay and branch validation. |
| `add_shortcode($tag, $callback)` | Partial/manual. Classifier accepts shortcode-shaped metadata and the extractor has a shallow shortcode-default rule. Runtime does not record `add_shortcode()` as a first-class HTTP entrypoint. | No automatic config. Requires page/content setup. | No. | **Manual analysis only.** Needs shortcode registration capture plus a page/post setup workflow. |
| `add_rewrite_rule()` | No first-class runtime capture. Classifier can mark supplied rewrite metadata as setup-required. | No automatic config. | No. | **Not supported.** Needs rewrite registration capture, route materialization, and request setup. |
| `add_rewrite_endpoint()` | No first-class runtime capture. Classifier can mark supplied rewrite metadata as setup-required. | No automatic config. | No. | **Not supported.** Needs endpoint registration capture, route materialization, and request setup. |
| `xmlrpc_methods` | Partial. Bootstrap sends `/xmlrpc.php` `system.listMethods`; classifier recognizes method-map records when method data is present. | No concrete method/body generator. Remains manual/setup-required. | No generated-config validation. | **Manual analysis only.** Needs concrete XML-RPC method extraction and a minimal method-call body. |

## Evidence and implementation locations

- HTTP mappings and REST materialization: `fuzzer/hook_energy/entrypoints.py`.
- Generator allowlist and seed status: `fuzzer/hook_energy/seed_generation/common_generator.py`.
- Config gating (`fuzzing_ready` versus `replay_only`): `fuzzer/hook_energy/seed_generation/config_exporter.py`.
- Callback validation and failure categories: `fuzzer/hook_energy/seed_generation/generated_config_runner.py`.
- Runtime REST registration capture: `web/instrumentation/hook_coverage/uopz_hook_wp.php`.
- Current admin-post method-gate artifact: `fuzzer/output/seed_generation/generated_config_summary.json`.

## Focused verification

The current checkout passed the focused entrypoint/generator/exporter/pipeline tests and the classifier/generated-runner/bootstrap tests. No production code was changed for this audit update.

## Remaining priorities

1. Add `admin_action_*` to the generated seed allowlist and cover its config/replay contract.
2. Produce bounded runtime proofs for `admin_post_*`, `login_form_*`, and both heartbeat hooks.
3. Keep shortcode, rewrite, and XML-RPC manual until their request setup data can be captured reliably.
