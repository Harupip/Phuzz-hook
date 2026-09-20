# Online-linked as the only WordPress workflow

Branch: `feature/separate-online-linked`. Changes are uncommitted and unstaged, on top of the package extraction documented in [the previous report](2026-09-20-online-linked-separation.md).

## User-visible result

`phuzz.ps1` now defaults to online-linked. Explicit `-Mode online-linked` still works. The five modes `default`, `seed-config`, `generated`, `zend` and `online` fail parameter validation before delegation. The mode-selection menu is removed; plugin selection remains for interactive invocation without a mode or plugin. `-DryRun` and explicit `-PluginSlug` do not prompt.

Zend discovery is always enabled. GeneratedConfigTimeoutSeconds, ZendMaxIterations, UseEntrypointPipeline, KeepDebugArtifacts and the unused ZEND_MAX_ITERATIONS setting are removed. The direct runner no longer accepts RunOnline, RunGeneratedConfigs or RunOnlineLinked. Existing direct linked calls must remove RunOnlineLinked; it was removed because PowerShell otherwise accepts the retired RunOnline name as an abbreviation. UseZendDiscovery and NoFollowLogs remain accepted for existing linked calls.

Example from `phuzz-main/code`:

```powershell
rtk proxy pwsh -NoProfile -File .\phuzz.ps1 -PluginSlug gamipress
```

## Source ownership and removal

- Deleted the old online coordinator and its lifecycle tests. Migrated the retained v0 validation and bootstrap selection tests to `test_online_common.py`.
- Removed the old wrapper dispatch and 13 exclusive PowerShell functions for generated batches, old Zend convergence, old retention and old final proof formatting. A caller scan found no remaining PowerShell/Python test callers for those functions.
- Simplified seed export to the runtime-only Zend exporter used by linked. Kept callback registry initialization, bootstrap/auth/nonce helpers and plugin setup. LearnPress nonce enrichment now targets the current campaign's suggested_seeds.json rather than the removed seed_generation workflow directory.
- Kept generated_config_runner and online_common as library dependencies of the linked coordinator/probe sender. Kept Zend convergence/Pass2/exporter libraries, CmpLog, instrumentation and normal fuzzer request/auth handling.
- Retained user configs, historical reports, independent tools and unrelated config-comparison WIP. Updated current entrypoint documentation and marked retired mode guides historical.

## Verification

- New mode/default tests first failed against the old behavior (10 assertions across 4 tests), then passed after removal.
- A direct-runner regression caught PowerShell interpreting RunOnline as RunOnlineLinked. Removing the redundant selector fixed the regression. The test now guards Docker through a failing stub so a future regression cannot start real containers.
- Full explicit-module unittest suite: **558 tests, OK, 2 skipped**, 39.067 seconds. Final test-isolation adjustment: 6 relevant tests OK, 17.266 seconds. The same local PHP test-ini workaround and explicit module naming documented in the extraction report were used.
- `git diff --check` passed; index remained empty. SHA256 checks confirmed all three previously identified config-comparison WIP files unchanged.
- Direct review: all 19 retained PowerShell helper bodies other than Export-LiveSeedSuggestions are unchanged. No current old-online coordinator imports or retired mode branches remain. Review was completed directly after the user requested no sub-agents; the newly started review agent was interrupted.

## Fresh Docker evidence

The first runtime attempt was invalidated when the abbreviation regression test unexpectedly entered Docker and recreated the shared web container. Its NOT_VERIFIED result is not counted as runtime proof. The clean rerun occurred after fixing the flag and completing the regression test.

1. Public wrapper, no Mode or UseZendDiscovery flag: `hookphuzz-online-discovery-fixture-20260921T004547Z`. Bootstrap, runtime seed export, registry initialization and v0 replay succeeded; exact callback reached. With 20 seconds per candidate and one candidate, it ended BOUNDED_ONLINE_COMPLETE/BUDGET_EXPIRED and exported zero final configs. This is bounded lifecycle proof, not Pass2 proof.
2. Fresh snapshot from that public run, unchanged seeds/registry, 90-second candidate budget, short output/config roots and a process-local Compose bind: `only-1789926439`. v0 replay_only advanced to v1 fuzzing_ready; **Pass2 accepted=1,total=1**; one final config was byte-identical to verified v1. Both workers stopped and terminal status was BOUNDED_ONLINE_COMPLETE/BUDGET_EXPIRED. No vulnerability is claimed.

Proof root: `C:\Users\chuda\.codex\tmp\only-1789926439`.
Candidate state: `online-linked/ead84234906713b2/state.json`.
Batch state/final configs: `online-linked/only-1789926439/`.
Logs: `.git/online-linked-separation/only-public-docker-clean.log`, `only-short-docker.log`, `only-full-final.log`.

The full Pass2 proof used short roots; the known Windows long-path limitation in the default artifact layout has not been fixed by this removal. LearnPress, runtime child registration and recovery were not newly exercised end-to-end in this turn. They retain existing tests; the fresh Docker proof covers the fixture's secondary AJAX callback.

Cleanup: the two web/db containers started for verification were stopped afterward; no volumes or pre-existing orphan containers were removed.
