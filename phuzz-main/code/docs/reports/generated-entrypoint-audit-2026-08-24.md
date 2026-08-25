# Generated Entrypoint Audit - 2026-08-24

Scope: current source, focused tests, generated-config artifacts, and available runtime callback evidence for WordPress entrypoints.

Interpretation: `direct_http_candidate` means the hook can be mapped to an HTTP template. It does not by itself mean that a PHUZZ config was generated or that the callback was reached. A generated config is `fuzzing_ready` only when the HTTP method and at least one fuzzable parameter are resolved; otherwise it may be `replay_only` or be skipped.

| Entrypoint type | Runtime capture / classification | Generated config | Callback proof | Current status and gap |
| --- | --- | --- | --- | --- |
| `wp_ajax_*` | Yes. Maps to `POST /wp-admin/admin-ajax.php` with fixed `action`. | Yes. Live seed generator, exporter, and generated-config runner support it. | Yes. Real-plugin and generated-config artifacts contain `callback_reached`. | **Supported and proven.** Auth, nonce, parameter provenance, and method evidence remain plugin-specific gates. |
| `wp_ajax_nopriv_*` | Yes. Longer nopriv prefix is matched before authenticated AJAX and maps to the same endpoint. | Yes, with `auth_mode=unauth-capable`. | Yes for runtime AJAX coverage; individual runs may be `expected_auth_skip` or `registered_not_executed` when the target requires the authenticated counterpart. | **Supported and proven as a family.** Do not treat every nopriv row as a failure. |
| `admin_post_*` | Yes. Bootstrap probes include `/wp-admin/admin-post.php?action=hookphuzz_probe`; normal hook registrations are classified. The LearnPress follow-up now selects only an active runtime-registered callback and correlates its exact action. | Yes when method evidence is resolved. The generic fixture and generated POST contract pass; the real LearnPress seed path is implemented but the current run stops during strict nonce mint/eval before config export. | The invalid LearnPress probe recorded exact action `lp_async_lp_background_single_course`, authenticated user `1`, nonce rejection, and no handler execution. The valid callback, parameter match, generated config, and final replay are not proven yet. | **Runtime method and exact action correlation are proven; real-plugin LearnPress remains BLOCKED at nonce-eval orchestration.** |
| `admin_post_nopriv_*` | Yes. Same registration/classification path as authenticated admin-post. | Yes when method evidence is resolved, with `auth_mode=unauth-capable`. | Unrelated nopriv candidates remain fail-closed. No nopriv LearnPress callback is claimed proven by this follow-up. | **Supported conditionally; no nopriv callback proof is complete.** |
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
- Current generic admin-post method-gate artifact: `fuzzer/output/seed_generation/generated_config_summary.json`.
- Current LearnPress strict invalid-nonce artifact: `fuzzer/output/seed_generation/zend-bridge/learnpress-20260825T163219Z/learnpress-probes/learnpress-20260825T163219Z-learnpress-invalid-nonce.json`.
- The completed LearnPress proof would be written to `fuzzer/output/seed_generation/learnpress-admin-post-nonce-proof.json`; the latest run did not emit it because valid replay was not reached.

## Focused verification

The LearnPress follow-up passed the focused admin-post/runtime contract tests (`7/7`), PowerShell parsing, PHP lint for the WordPress override, and `git diff --check`. The broader Zend REST baseline remains the recorded `3 failures, 1 error`; REST/convergence code was not modified in this follow-up.

## 2026-08-25 LearnPress admin-post follow-up

### What changed

- `scripts/wordpress/run-wordpress-phuzz.ps1` now selects one active LearnPress `admin_post_*` callback from the live runtime registry, instead of deriving the endpoint or parameter from source text. The selected current candidate is `admin_post_lp_async_lp_background_single_course`, with action `lp_async_lp_background_single_course` and callback `LP_Background_Single_Course->maybe_handle`.
- The script sends an exact `POST /wp-admin/admin-post.php` request with a fixed action. It first sends `_nonce=hookphuzz-invalid-nonce` as a negative control, then evaluates the real LearnPress nonce and the original WordPress `wp_verify_nonce()` result in the same authenticated container context, and only then attempts the valid request.
- The script keeps `action` and `_nonce` fixed. Only a parameter path observed in correlated Zend runtime evidence may be injected into generated seeds and fuzzed. It also retains a fail-closed check for unrelated admin-post candidates.
- `web/applications/wordpress/_overrides/99-wordpress.php` keeps the normal nonce overrides disabled under strict proof mode. In strict mode it records the nonce/action/auth context and attempts callback execution observation; it does not change LearnPress source or the REST/AJAX paths.
- `tests/test_learnpress_admin_post_proof.py` adds focused contract checks for the fixed POST/action/nonce flow, the original verifier requirement, the negative control, and fail-closed unrelated-candidate handling.

### Evidence and current boundary

The latest run is `learnpress-20260825T163219Z`. Its invalid-nonce artifact contains:

```json
{
  "nonce_action": "lp_async_lp_background_single_course",
  "authenticated_user_id": 1,
  "authenticated": true,
  "handler_executed": false,
  "nonce_rejected": true
}
```

A direct equivalent WordPress CLI evaluation returned a valid LearnPress nonce and original-core `wp_verify_nonce()` result `1` for user `1` in the authenticated context. That proves the nonce primitive can be minted and verified, but it is not yet the final end-to-end proof because the PowerShell orchestration received no JSON from its nonce-eval helper and failed closed before the valid callback request.

Therefore the current status is **not PASS**. The missing proof is the valid request reaching the correlated LearnPress callback, at least one observed non-`action`/non-`_nonce` parameter path matching, generated POST config export, and a successful fresh final replay. The next investigation should compare the PowerShell helper's captured output/type and JSON extraction with the direct `docker exec ... wp-cli eval` command; do not weaken strict verification or replace it with equality-only matching.

## Remaining priorities

1. Add `admin_action_*` to the generated seed allowlist and cover its config/replay contract.
2. Resolve the LearnPress strict nonce-eval orchestration blocker, then complete the valid parameter probe, generated POST config, and fresh final replay.
3. Produce bounded runtime proofs for `login_form_*` and both heartbeat hooks.
4. Keep shortcode, rewrite, and XML-RPC manual until their request setup data can be captured reliably.
