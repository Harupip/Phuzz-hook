# Cookie Notice version investigation — 2026-11-02

Read-only investigation of `Cookie_Notice::deactivate_plugin`, hook `wp_ajax_cn-deactivate-plugin`, using run `cookie-notice-20261102T091138Z`, candidate storage `d63577cc1cca3aa6`. These artifacts predate the callback-baseline migration; their trial/Pass 2 fields describe the old pipeline, not the new flow. No deduplication fix or plugin config completion is claimed here.

## Versions observed

Every config fixes query `action=cn-deactivate-plugin`. Versions v1–v6 are POST; v0 is GET.

| Version | Parent | Body fixed | Body fuzz | What happened |
| --- | --- | --- | --- | --- |
| v0 | none | none | none | Bootstrap, only query action; replay-only discovery |
| v1 | v0 | nonce=probe | none | p1 submitted nonce; Zend read nonce and tested isset(option_id); replay-only |
| v2 | v0 | none | option_id | p2 submitted option_id=probe; admitted option_id; not a complete normal application request because nonce is absent |
| v3 | v0 | nonce=probe | option_id | p3 submitted nonce=probe and option_id=probe together; both read in the same request |
| v4 | v0 | nonce=probe | option_id | p4 submitted the same two fields in reverse order; no new parameter or proven new path relative to v3 |
| v5 | v4 | nonce=probe | option_id, other | p5 submitted option_id=8uzz and other=probe; integer cast opens option 8 and reads other |
| v6 | v5 | nonce=probe, other=fuzz | option_id | A later request used option_id=fuzz; other was not read and became fixed in the proposed config; no new parameter name |

v1–v4 are siblings from v0, not a cumulative v1→v2→v3→v4 chain. Historical direct exports were v3, v5 and v6. v3 superseded v2; v6 superseded v4; v0/v1 were excluded from final fuzz-ready exports. Historical v1–v6 replay gates recorded Pass 2 1/1; this is not a fuzzing or complete-branch PASS.

## Same-request multi-parameter evidence

- p3: request `r-2752ceb9b8018ff8bd846476`, POST body nonce=probe, option_id=probe. Attributed reads in the same callback: nonce at line 1197; option_id at line 1201. v3 contains both fields.
- p4: request `r-a9e9707414f133cd42315081`, same body values with field order reversed.
- p5: request `r-dbb28caef0463d24773d3ee9`, POST body option_id=8uzz, nonce=probe, other=probe. Attributed reads: nonce, option_id and other (line 1205). Thus option_id and other, the two fuzz selectors of v5, were read in one request.
- For p3 and p5, request/Zend IDs and run IDs matched, the expected callback executed and dropped_event_count was zero. Repeated isset/read events for option_id were not separate parameter identities.

Relative evidence root (local historical outputs are not included in this commit):

```text
phuzz-main/code/fuzzer/output/online-linked/cookie-notice-20261102T091138Z/
  campaigns/d63577cc1cca3aa6/state.json
  campaigns/d63577cc1cca3aa6/versions/v0/probe/p3/{request,zend}/r-2752ceb9b8018ff8bd846476.json
  campaigns/d63577cc1cca3aa6/versions/v4/probe/p5/{request,zend}/r-dbb28caef0463d24773d3ee9.json
  final-config-summary.json
```

## Why v4 duplicated v3 — still unfixed

Coordinator `_config_request_key()` preserves the order of named body data rows. v3 has nonce then option_id; v4 has option_id then nonce. Offline calls against the real configs produced different keys. Sorting only those named body rows in memory produced equal keys. This PHP callback indexes POST by name, so those two orders do not change its behavior.

Exporter comparison additionally retains `metadata.seed_variant_id`: v3 uses `zend_probe_post_option_id`; v4 uses `zend_probe_post_nonce`. After the existing removal of transient request/run provenance, this was their only metadata difference. An in-memory comparison excluding that field let `_covers_version()` recognize compatible coverage. Exported bytes were not modified.

A separate generic weakness was found in the probe path: it selects the matching target parameter from a successful probe, while other co-observed accepted fields can require separate handling; method-transition materialization already carries multiple observed fields. A future fix should admit all eligible same-request fields with their own correlation checks, deduplicate identities by name/source/location, and recognize equivalent named parameter order/probe provenance. Preserve real method/auth/transport/fixed-value and fuzz/fixed differences. Do not sort meaningful JSON arrays or union arbitrary branch contexts. Missing a previously seen field alone does not prove a newly discovered path.

Retest expectation after a future dedup fix: repeating the p3/p4 request should not create another version or handoff. Keep the basic input case separate from the option-8 case where other is used. Do not assume the final number of configs proves branch coverage.

## Nonce in actual plugin code

In the inspected Cookie Notice 2.4.8 source:

- `cookie-notice.php:1052` creates `wp_create_nonce('cn-deactivate-plugin')` on the Plugins admin page and exposes it through `cnArgsPlugins.nonce`.
- `js/admin-plugins.js:27-31` sends action, option_id, other and nonce together when Deactivate & Submit is clicked.
- `cookie-notice.php:1197` checks install_plugins capability and `wp_verify_nonce($_POST['nonce'], 'cn-deactivate-plugin')` before the option_id logic. Only integer option_id=8 reads other.

Therefore nonce is part of the normal request from the start; its absence in generated v2 reflects discovery/config construction, not normal UI behavior. `probe` is a fuzzer placeholder, not a production nonce. The harness override in `_overrides/99-wordpress.php` returns nonce success unless `HOOKPHUZZ_STRICT_NONCE_PROOF=1`; the historical campaign's active strict setting was not independently rechecked. Do not infer nonce validity outside the instrumented harness.

## Timing in this historical run

| Component | Recorded duration |
| --- | --- |
| Final version write | 0.015–0.032 seconds |
| Probe | 1.578–4.391 seconds |
| Child replay including verification | 1.312–2.204 seconds |
| Stop/start worker handoff | 1.219–1.578 seconds |
| v4 worker start to first other probe | 57.125 seconds (discovery, not config writing) |

For redundant v4: p4 probe 1.734 + write 0.016 + replay 1.672 + handoff 1.562 = about 4.984 measured seconds. This excludes the separately unmeasured trial, initial config materialization and checkpoints; nested timing fields must not be summed again. These are old-pipeline measurements, not a benchmark of the new baseline flow.

Today's separate implementation removed trial/Pass 2 but did not fix duplication. See [migration verification and cross-machine retest notes](2026-11-02-callback-baseline-verification.md) for the new behavior, offline results and the interrupted runtime attempt.
