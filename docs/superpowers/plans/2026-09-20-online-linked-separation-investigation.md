# Online-linked separation: investigation and proposed plan

Date: 2026-09-20. The user subsequently authorized the same-repository extraction on a new branch. Implementation and verification results are recorded in [the separation report](../../../phuzz-main/code/docs/reports/2026-09-20-online-linked-separation.md). The investigation below preserves the original proposal and alternatives.

**Goal:** Isolate the orchestration and functionality exclusive to `online-linked`, while preserving the other modes and shared runtime behavior.

**Architecture:** Recommended first step is a dedicated `fuzzer/online_linked/` package inside this repository. It owns campaign orchestration, version transitions, evidence consumption, probes, replay trials, and final export. It consumes shared discovery, configuration, verification, request preparation, and PHUZZ execution services.

**Tech stack:** Existing Python, PowerShell, Docker Compose, WordPress instrumentation, unittest. No new framework or dependency.

**Design basis:** This document records the requested investigation and proposed design together. “Separate” has not yet been clarified as a package, a separate repository, or removal; the main plan assumes a package. Alternatives appear at the end. No product code has been changed and no test/Docker baseline has been run for this audit.

## 1. Snapshot and constraints

- Inspected branch: `feature/import-02-0day-vulns`, HEAD `c2c5e73` (`Make vulnerability stop threshold configurable`). Findings refer to the current working tree, not only HEAD.
- Existing WIP includes modified `fuzzer/config_comparison/README.md`, untracked `config_comparison/online_linked.py`, `tests/test_online_linked_config_comparison.py`, generated online-linked configs, plans, and experiment data. Preserve all of it.
- Existing `online` remains a separate supported mode. It is not another name for `online-linked`.
- Preserve CLI values/defaults, config hashes, artifact schemas, candidate identity, lineage, auth context, request/run correlation, replay and Pass 2 gates, recovery, deadlines, and the current configurable vulnerability-stop behavior.
- Do not combine extraction with a discovery algorithm change, a campaign-stop fix, or a rewrite of the 3,717-line coordinator.
- A function with another production or test caller is not exclusive/dead code. Reclassify it as shared; do not delete it as incidental cleanup.
- All paths below are relative to `phuzz-main/code/` unless stated otherwise. Line numbers describe the inspected snapshot and will move after edits.

## 2. Current dependency map

```text
phuzz.ps1 -Mode online-linked
  -> scripts/wordpress/run-wordpress-phuzz.ps1 -RunOnlineLinked
     -> shared Docker/plugin/bootstrap/seed export/registry setup
     -> online_linked_coordinator.py::run_online_linked
        -> campaign queue + one OnlineLinkedCoordinator per candidate
        -> v0 selection + replay/provenance/Pass 2 gate
        -> immutable worker + correlated runtime evidence
        -> parameter child / pending probe / replay input trial
        -> child replay + Pass 2 + worker handoff/recovery
        -> runtime HTTP registration -> candidate queue
        -> online_linked_export -> final-configs

coordinator -> online_config_runner helpers AND OnlineCoordinator._select_v0
coordinator -> generated_config_runner + Zend bridge + config/convergence
probe_sender -> docker exec /app/fuzzer.py --online-linked-probe
probe_sender -> fuzzer.prepare_request_from_config -> shared _prepare_request
```

Evidence anchors:

| Source | Boundary established |
| --- | --- |
| `phuzz.ps1:316` | Mode dispatch forwards linked budgets to the WordPress runner. |
| `scripts/wordpress/run-wordpress-phuzz.ps1:1526` | `online` and `online-linked` share isolated seed export setup. |
| `scripts/wordpress/run-wordpress-phuzz.ps1:1541` | Linked branch initializes registry, stops bootstrap worker, sets Compose context, invokes coordinator, reports state. |
| `hook_energy/seed_generation/online_linked_coordinator.py:21` | Imports shared generated execution, online helpers, Zend bridge, config export, convergence, entrypoint and method resolution. |
| `hook_energy/seed_generation/online_linked_coordinator.py:2959` | Fallback constructs the old `OnlineCoordinator` and calls its private `_select_v0()`. |
| `hook_energy/seed_generation/online_linked_coordinator.py:3506` | Batch queue, candidate budgets, runtime registration expansion, aggregate state and final export. |
| `hook_energy/seed_generation/probe_sender.py:52` | Probe launches through `fuzzer.py --online-linked-probe`. |
| `fuzzer.py:1055` | Linked-only command dispatch inside the generic fuzzer entrypoint. |
| `fuzzer.py:73` and `fuzzer.py:688` | `_prepare_request()` also serves normal fuzzing; auth/request behavior cannot move wholesale into linked mode. |
| `docker-compose.yml:70` and `docker-compose.yml:80` | Existing fuzzer image context and whole `./fuzzer:/app` bind mount. |

The historical description of linked mode as a single canonical v0 without action expansion is not an adequate description of this checkout. Current source contains a batch queue, runtime candidate discovery, and replay input trials.

## 3. Ownership classification

### Move as online-linked implementation

| Existing file | Proposed file | Responsibility |
| --- | --- | --- |
| `hook_energy/seed_generation/online_linked_coordinator.py` | `online_linked/coordinator.py` | Initially preserve its class and functions intact. |
| `hook_energy/seed_generation/online_linked_evidence.py` | `online_linked/evidence.py` | Runtime artifact batch consumption. |
| `hook_energy/seed_generation/online_linked_replay_inputs.py` | `online_linked/replay_inputs.py` | Correlated comparison hints and replay input proposals. |
| `hook_energy/seed_generation/online_linked_export.py` | `online_linked/export.py` | Export latest config whose recorded gates and hash satisfy the contract. |
| `hook_energy/seed_generation/probe_sender.py` | `online_linked/probe_sender.py` | Bounded sender in the existing worker, parent inspection, artifact wait. |

Add only `online_linked/__init__.py` and `online_linked/__main__.py` as package/CLI entrypoints. Keep existing test filenames flat so unittest discovery behavior stays stable; migrate imports and patch targets.

Mode-specific behavior inside the coordinator includes candidate identity/deduplication, campaign queue/limits, immutable version lineage, runtime candidate admission, branch-opening replay trials, pending probes, parent handoff/recovery, and linked terminal/export policy.

### Retain as shared services

- `hook_energy/seed_generation/generated_config_runner.py`: replay/execution and artifact functions already serve generated and online callers. Retain the implementation and existing imports initially; its name alone does not make it generated-exclusive.
- `seed_generation/config/config_exporter.py`, `seed_generation/convergence/convergence.py`: config generation, replay-only materialization and convergence.
- `hook_energy/seed_generation/zend_runtime/bridge_cli.py`, `zend_discovery/engine.py`: convergence targets, provenance admission and Pass 2 verification.
- `discovery/entrypoints/entrypoints.py`, `discovery/entrypoints/method_resolution.py`: entrypoint construction and HTTP method resolution.
- `fuzz_guidance/cmplog/hints.py`, generic mutation, coverage, vulnerability finding and stop policy.
- Zend extension, WordPress UOPZ instrumentation and artifact producers. The consumer being linked-specific does not make the producer exclusive.
- Docker, WordPress setup, plugin selection, authentication, REST bootstrap, registry setup and seed export.
- `_prepare_request()` and its auth/header/cookie handling, used by ordinary fuzzing too.
- COOKIE admission support: `runtime_cookie_probes` also appears in the Zend bridge CLI/engine and tests. Keep the shared capability and its opt-in behavior; linked-specific probe scheduling belongs in the new package.

### Must untangle, not move blindly

1. **Old online coordinator dependency.** Extract the shared v0-selection behavior and the small helpers currently imported from `online_config_runner.py`. Proposed home: `hook_energy/seed_generation/online_common.py`. Keep it limited to actual shared functions: hash, validation and its helper closure, artifact loading, JSON writes, selector/decorator/target matching needed by both callers. Do not relocate the old coordinator class or its worker loop.
2. **Generic fuzzer importing linked mode.** Make the sender executable with `python -m online_linked.probe_sender`; remove the linked-specific branch from `fuzzer.py` after all callers migrate. Move the config-to-request adapter (`prepare_request_from_config`, `_config_request_params`) to the sender if caller audit still shows only sender/test callers. Preserve `_prepare_request()` in the generic runtime. Extracting the whole HTTP runtime is outside this plan.
3. **Wrapper wiring.** Isolate the linked launch block in a small `scripts/wordpress/invoke-online-linked.ps1` function/script taking explicit paths, IDs, service, budgets and Compose context. Bootstrap stays shared. `phuzz.ps1 -Mode online-linked` remains a compatible dispatch alias.
4. **Settings.** `OnlineTimeoutSeconds` and `OnlineMaxVersions` belong to both online modes. Candidate/campaign limits currently feed linked mode only. Do not rename existing `ONLINE_*` settings during extraction; retain parsing in `read-phuzz-env.ps1` and pass relevant values at dispatch.
5. **Offline comparison WIP.** `config_comparison/online_linked.py` reads linked final configs/batch state and calls the generic comparison engine. Keep it as an output consumer, not a runtime dependency of the coordinator. It and its untracked test must be included in compatibility checks, without overwriting or staging unrelated WIP.

## 4. Proposed extraction tasks

### Task 1 — Capture baseline and pin boundaries

- [ ] Record current status and exact WIP paths before any checkout/staging.
- [ ] Re-run caller/import searches over tracked and untracked source, excluding generated experiment/plugin corpora where appropriate.
- [ ] Run the focused unit suite below, with its outer timeout. Record failures as baseline failures, not extraction regressions.
- [ ] Pin missing behavior tests around bootstrap fallback, replay-only v0, hash/export verification, parent-stop-before-child, failed-child recovery, candidate dedupe/budgets, guest/auth requests and shared mode defaults.
- [ ] Preserve representative state/config fixtures for comparison; normalize only timestamps, run IDs and workspace roots, never correlation identities, input placement or gate results.

Deliverable: reproducible baseline and exact caller inventory. Stop deletion work if a proposed exclusive function still has an unrelated caller.

### Task 2 — Remove dependency on the old online coordinator

Files: `online_config_runner.py`, `online_linked_coordinator.py`, `online_linked_export.py`, new `online_common.py` in the same directory; affected online/linked/export tests.

- [ ] Move only the shared helper closure and selector into `online_common.py`, preserving callable signatures and return shapes wherever possible.
- [ ] Make `OnlineCoordinator._select_v0()` delegate to the extracted selection behavior.
- [ ] Make linked fallback invoke that shared function directly instead of constructing `OnlineCoordinator`.
- [ ] Redirect linked export's `config_hash` import and update all actual callers.
- [ ] Verify normal online selection remains fuzz-ready-only while linked's primary selection still permits replay-only candidates.
- [ ] Run online, linked coordinator and export unit tests with bounded execution.

Deliverable: linked runtime no longer imports `online_config_runner` or constructs its coordinator; the old online mode still owns its lifecycle.

### Task 3 — Relocate the linked implementation and its CLI

Files: five moves in section 3, new `online_linked/__init__.py`, `online_linked/__main__.py`; five linked/probe test files.

- [ ] Move code mechanically; update internal imports and test mock patch targets together.
- [ ] Replace the current `Path(__file__).resolve().parents[2]` assumption with the correct package/module entrypoint behavior; test from the wrapper working directory and `/app`.
- [ ] Use `python -m online_linked` with the existing argument names and defaults, running with the fuzzer root available on the import path.
- [ ] Preserve `configs/online-linked`, `output/online-linked`, batch/state paths, config mirrors, version directory layout and state field names.
- [ ] Update callers to the new entrypoint. Remove old entrypoint files once the caller inventory is empty; add a temporary forwarding entrypoint only if an identified external caller needs it, with a defined removal step.
- [ ] Run linked evidence, replay-input, coordinator and export suites.

Deliverable: the linked policy/implementation lives in one package; changes to file placement have not changed runtime semantics.

### Task 4 — Decouple probe launch from generic fuzzer dispatch

Files: `online_linked/probe_sender.py`, `fuzzer.py`, `tests/test_probe_sender.py`, `tests/test_request_auth_context.py`.

- [ ] Change the docker exec invocation to `python -m online_linked.probe_sender`, preserving every existing request/run/callback/method/auth/timeout argument.
- [ ] Move only the sender-exclusive config adapter after confirming its caller list; keep the shared request assembly used by `Fuzzer.prepare_request()` intact.
- [ ] Remove `--online-linked-probe` dispatch once no internal caller uses it. If there is a verified external consumer, migrate it or explicitly time-bound a compatibility alias.
- [ ] Verify sender output/error shape, correlation, deadline handling, parent exit inspection, and the normal fuzzer entrypoint.
- [ ] Verify GET/form/JSON placement and authenticated/guest request equivalence using existing request tests.

Deliverable: generic fuzzer startup has no import or command branch for linked mode; linked probes still use the same request semantics.

### Task 5 — Narrow PowerShell integration and retain data consumers

Files: new `scripts/wordpress/invoke-online-linked.ps1`, `scripts/wordpress/run-wordpress-phuzz.ps1`, `phuzz.ps1`, `tests/test_phuzz_wrapper_contract.py`, current run/flow guides. Settings parser and `phuzz.env` need changes only if dispatch cannot preserve current values without them.

- [ ] Extract linked launch/orchestration lines into the dedicated script/function; do not duplicate plugin/bootstrap/registry setup.
- [ ] Preserve bootstrap worker stop ordering and restore `COMPOSE_FILE` in `finally` on success/failure.
- [ ] Update wrapper help/path checks for the new module location while keeping the current public mode and flags.
- [ ] Leave `online`, `generated`, `zend`, `default` and `seed-config` dispatch behavior intact.
- [ ] Check the offline comparison WIP against unchanged final-config/state outputs and update only necessary import/path references.
- [ ] Run wrapper contract and comparison tests; update active usage guides. Historical reports remain historical records, not broken production callers to erase.

Deliverable: shared wrapper contains a small explicit linked dispatch; mode-specific launching has a clear owner.

### Task 6 — Validate architecture and runtime parity

- [ ] Add one import-boundary check: shared Python runtime must not import `online_linked`; linked code must not import the old `online_config_runner`. Exclude deliberate CLI dispatch and tests from the appropriate rule.
- [ ] Run the focused suite, then the full existing unit suite with an explicit outer timeout (for example 600 seconds). A timeout is an incomplete check, not PASS.
- [ ] Run bounded Docker fixture proof for v0 readiness, correlated parameter discovery, child replay and Pass 2, parent handoff/recovery and verified final export. Use a fresh run ID and retain artifact paths.
- [ ] Exercise at least one runtime registration child and a branch-opening replay-input trial where the fixture supports them; missing proof is `NOT_VERIFIED`, not inferred from mock tests.
- [ ] Run representative non-linked generated/Zend and old online smoke checks to detect shared-helper regressions. Keep budgets explicit and use the configured stop policy.
- [ ] Inspect the diff and status, then stage only approved extraction paths if implementation is later requested. No broad `git add .`.

Deliverable: code boundary proof plus separate unit/runtime results. HTTP 200, a started container, exit code 0, or callback reachability alone does not prove replay/Pass 2 or vulnerability success.

## 5. Bounded baseline command

Run from `phuzz-main/code` with Python dependencies available. This command is proposed and has NOT been executed in this investigation:

```powershell
rtk proxy python -c "import subprocess,sys; suites=['fuzzer.tests.test_online_linked_coordinator','fuzzer.tests.test_online_linked_evidence','fuzzer.tests.test_online_linked_replay_inputs','fuzzer.tests.test_online_linked_export','fuzzer.tests.test_probe_sender','fuzzer.tests.test_online_config_runner','fuzzer.tests.test_generated_config_runner','fuzzer.tests.test_phuzz_wrapper_contract','fuzzer.tests.test_request_auth_context','fuzzer.tests.test_online_linked_config_comparison']; sys.exit(subprocess.run([sys.executable,'-B','-m','unittest',*suites],timeout=180).returncode)"
```

The comparison suite belongs to current WIP. If execution happens from a clean isolated checkout, explicitly include the authorized WIP snapshot or report that suite as unavailable; do not silently claim it passed.

Additional shared regression coverage: `test_zend_discovery`, `test_seed_to_config_exporter`, `test_seed_validator`, `test_cmplog` and existing extension checks as supported by the environment. Separate tests needing compiled instrumentation/Docker from pure unit results.

## 6. If the intended destination is a separate repository

Complete the boundary extraction first. Moving only the five linked files will not produce a runnable standalone project: it still needs the config/convergence/verification code, runtime instrumentation, fuzzer worker, Docker service/mount conventions, auth/bootstrap and correlated artifacts.

Choose one concrete delivery contract before that second stage:

1. **Thin external controller:** linked orchestration in a separate repo, consuming a pinned HookPhuzz runtime/image and its documented commands/artifacts. Extract a small shared Python package only for functions the controller actually needs, or retain a pinned dependency on the existing runtime source during transition. Do not invent a remote service API merely to change repository ownership.
2. **Independent full distribution:** ship the required shared runtime too, preserving its licenses and tracking upstream fixes. This creates maintenance of a distribution/fork, not just moving linked-exclusive code.

For either, replace implicit cwd/import roots and host-specific absolute paths with explicit workspace/runtime roots, version the artifact/CLI contract, define config and artifact mounts, and prove a clean clone can launch the pinned runtime. This is additional scope beyond a same-repository package.

## 7. If the intent is removal from the current repository

The removal plan is smaller than extraction and should not perform the preceding relocation work unnecessarily:

- Remove linked mode/menu/dispatch and linked-only candidate/campaign settings, then linked-only coordinator/evidence/replay-input/export/probe files and their dedicated tests after caller verification.
- Remove the probe dispatch and sender-only adapter from `fuzzer.py` only when no remaining production/test caller requires them. Keep shared request/auth helpers.
- Keep mode `online`, its timeout/version settings, generated/Zend execution, convergence/Pass 2, CmpLog, instrumentation and shared COOKIE support.
- Decide explicitly whether the untracked linked comparison CLI should be retained as a reader of historical outputs. Preserve existing configs, artifacts, experiments and evidence unless their deletion is separately requested.
- Update active documentation and mode contract tests. Do not delete historical reports simply because they mention the removed mode.
- Verify no active production reference to removed entrypoints remains, and run remaining-mode regression checks.

## 8. Recommendation and completion criteria

Start with a same-repository package if the intent is to keep developing/running online-linked independently. It gives a real ownership boundary without duplicating the runtime. Avoid splitting the large coordinator into many classes during this move; that is a separate design decision after parity is proven.

Extraction is complete when:

1. Linked-exclusive orchestration is located in the dedicated package/launcher.
2. Linked runtime does not instantiate/import the old online coordinator.
3. Generic fuzzer and shared discovery/verification modules do not import the linked package.
4. Existing public dispatch, budgets, artifact contracts and other modes retain behavior.
5. Focused/full checks and fresh Docker evidence establish the stated scope; missing runtime proof is explicitly `NOT_VERIFIED`.

Investigation result: source-level boundaries above are verified in the current checkout. Implementation, test baseline and fresh runtime parity remain unexecuted.
