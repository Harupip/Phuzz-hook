# Stage A - HTTP method inference investigation

Branch: `feature/http-method-inference`

Pre-change commit: `677781fb4b3950feceba0c4129b12a1537c03f87`

Immutable GamiPress workspace: `research/real-plugin-e2e/gamipress/20260731-234828-gamipress`

Pre-change workspace fingerprint: 334 files; aggregate SHA-256 `a3153291b9a887ba42dd96dbb8017fdfff7a7897371f0b2376b7ac01e1d6a0fc` (sorted per-file SHA-256 rows, then SHA-256 of the joined rows).

## Root cause

The primary root cause is not the AJAX prefix table itself. It is the fallback injected after prefix matching:

- `phuzz-main/code/fuzzer/hook_energy/entrypoints.py:7` defines `DEFAULT_HTTP_METHOD_FALLBACK = "POST"`.
- `phuzz-main/code/fuzzer/hook_energy/entrypoints.py:207-230` maps every direct hook without an explicit `fallback_method` to that POST value. AJAX, admin-post, login-form, and heartbeat entries therefore acquire POST before parameter or runtime evidence is considered.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/generator.py:361` calls the endpoint template again when no usable source/runtime evidence exists and turns that template POST into a runnable `fallback` seed.

The previous method-inference implementation therefore moved the default rather than removing it. The comment says the method is resolved later, but the endpoint template still contains POST and downstream consumers accept it as concrete.

## Secondary defaults and unsafe conversions

- `phuzz-main/code/fuzzer/hook_energy/seed_generation/generator.py:346-351` converts an unobserved `REQUEST` source into separate GET and POST runnable seeds. This records low confidence but still creates fuzzing-ready configs, so ambiguity is not fail-closed.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/generator.py:352-360` labels direct GET/POST source evidence as generic `parameter_source` with `medium` confidence instead of the required `source_exact` provenance.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/generator.py:326-339` can accept correlated runtime metadata, but `generator.py:288-291` refuses to generate seeds for covered callbacks. Consequently the normal uncovered-seed flow cannot use the executed-callback observation that would make `REQUEST` evidence useful.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/generator.py:375-387` accepts only an executed-callback row containing matching callback identity, request ID, `http_method`, and target plugin. This is a sound correlation gate, but the policy is embedded in the generator rather than shared by all paths.
- `phuzz-main/code/fuzzer/hook_energy/recursive_child_hook_seeds.py:305-312` consumes the endpoint template and silently converts a missing method to GET. This is a separate missing-evidence fallback.
- `phuzz-main/code/fuzzer/hook_energy/entrypoints.py:202-204` defaults REST metadata with no declared method to GET. Declared REST methods are preserved when present, but missing declarations are not ambiguous.
- `phuzz-main/code/fuzzer/hook_energy/phuzz_config_writer.py:21-29` and `seed_generation/config_exporter.py:246-259` treat any non-empty upstream method as authoritative; neither resolves provenance nor blocks low-confidence fallback methods.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/importer.py:104-119` imports the concrete method and provenance verbatim. It does not create POST, but it propagates the upstream fallback into the replay queue.
- `phuzz-main/code/fuzzer/fuzzer.py:232-235,405-419,517-541` consumes config `methods` and sends the selected verb. It has no POST default in this path; it faithfully executes the incorrect generated config.
- `phuzz-main/code/fuzzer/hook_energy/seed_validator.py:43-76,99-105` also sends the concrete upstream method. Its method allowlist is not a default.
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py:81-190` selects generated configs and validates fresh request artifacts. It does not infer a method; the method has already been fixed in the config.
- `research/hookphuzz-opcode/phase9/generator/generate_configs.php:22,27`, `research/hookphuzz-opcode/phase10/scripts/validate.py:63`, and `research/hookphuzz-opcode/phase10-gamipress-ajax/collector/generate_config.py:9-11` contain independent POST assumptions in preserved research harnesses. They are outside the production seed pipeline and must remain unchanged for the requested Phase 9/10 regression boundary.

## End-to-end data flow before modification

1. **Runtime observation artifacts.** `phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php:43-46` records request ID, HTTP method, target plugin, target, endpoint, and input signature. Lines `813-850` copy request ID/method/plugin into the executed-callback row. Lines `1355-1439` merge the most recent executed-callback provenance into `total_coverage.json`.
2. **Entrypoint discovery.** `phuzz-main/code/fuzzer/hook_energy/bootstrap_entry_discovery.py:281-333` normalizes registered/executed callback maps. `entry_classifier.py:196-220` calls `direct_http_details()`, which adds endpoint/action/auth metadata and the fallback method.
3. **Static parameter extraction.** `seed_generation/input_extractor.py:13-21,95-127` recognizes direct superglobals and `filter_input`; `REQUEST` is retained as `body_or_query` rather than resolved.
4. **Runtime/static merge.** `seed_generation/generator.py:129-169` extracts static inputs from the registered row and attaches the matching executed row as `_executed_callback`. There is no central method result object; static sources and runtime metadata meet only inside `_method_decisions()`.
5. **Seed generation.** `generator.py:280-361` clones the endpoint template per decision, places `action`, attaches extracted parameters, and currently creates concrete variants for ambiguous REQUEST and fallback cases.
6. **Config export.** `seed_generation/config_exporter.py:15-80,86-123` copies seed methods and parameter sections into PHUZZ JSON. Lines `299-350` copy the old `method_source`, `method_confidence`, and `method_evidence` fields into metadata and summary rows.
7. **Generated-config replay.** `generated_config_runner.py:81-190` invokes each generated config, gathers only new artifacts, and evaluates expected callback execution. PHUZZ reads `methods` in `fuzzer.py:232-235` and prepares the request in `fuzzer.py:517-541`.
8. **Validation/reporting.** `seed_validator.py:79-155` diffs request artifacts and reports callback evidence separately from HTTP status. `generator.py:457-499` summarizes method counts/sources, but it currently counts ambiguous expansions as resolved seeds and fallback POST as a valid method.

## GamiPress propagation

The immutable real-plugin workspace already records the correct raw facts:

- `results/parameter-observations.json` records `source=REQUEST`, correlated `observed_method=POST`, request ID, callback, source file/line, operation, and marker hash.
- `scripts/common.py:14-26` returns the unique observed method for REQUEST and returns `None` when no observation exists.
- `scripts/generate-config.py:6-9` converts that result into the POST config, but the exported summary uses free-text `method_source` and omits the normalized confidence/candidate fields required by this task.
- `scripts/replay-config.py:6-18` replays POST and gates callback/parameter proof on the same request ID.
- `results/replay-summary.json:2-11` shows callback, parameter, and request-ID correlation PASS. HTTP 200 is present but is not the proof gate.

Thus the existing GamiPress POST is evidence-backed for that observation, but neither the immutable generated config nor the production schema explicitly labels it `runtime_observed`. The preserved workspace will not be edited; a new regression artifact must apply the central policy to those immutable observations.

## Planned correction

- Add one central resolver returning `resolved_method`, `candidate_methods`, `method_evidence`, `method_confidence`, `observed_request_method`, and `route_declared_methods`.
- Use `source_exact`, `route_declared`, `runtime_observed`, and `ambiguous` as deterministic confidence values.
- Represent unobserved REQUEST and all missing-method cases as `method=null`, `method_status=ambiguous`, candidates `GET`/`POST`; do not export or replay them.
- Expand declared multi-method REST routes and exact mixed GET/POST sources into one seed/config per method.
- Move the fixed AJAX/admin-post action to query or body only after a method is resolved.
- Preserve legacy artifacts that already contain a method, but label them as legacy rather than newly inferred evidence.

