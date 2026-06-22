# Generated Config Batch Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in sequential execution of generated PHUZZ configs with per-config timeout cleanup and a JSON run summary.

**Architecture:** A Python stdlib CLI owns deterministic summary parsing, Docker one-off execution, timeout cleanup, and result writing. The existing PowerShell runner only exposes switches and invokes that CLI after seed conversion, preserving its default path when the switch is absent.

**Tech Stack:** Python 3 stdlib, `unittest`, PowerShell 5, Docker Compose.

---

### Task 1: Python generated-config batch runner

**Files:**
- Create: `phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py`
- Create: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`

- [ ] **Step 1: Write failing tests**

Add tests that call the wished-for `load_config_slugs()`, `run_generated_configs()`, and `main()` APIs. Use a fake command runner returning `subprocess.CompletedProcess` or raising `subprocess.TimeoutExpired`. Assert ordered runs, `passed`/`failed`/`timed_out` counts, timeout `docker rm -f` cleanup, continuation after failure, malformed-summary rejection, CLI exit codes, and written JSON.

```python
def test_timeout_cleans_container_and_continues(self):
    runner = FakeRunner([subprocess.TimeoutExpired(["docker"], 5), completed(0)])
    report = run_generated_configs(["generated-hooks/one", "generated-hooks/two"], timeout_seconds=5, run_command=runner)
    self.assertEqual([row["status"] for row in report["runs"]], ["timed_out", "passed"])
    self.assertIn(["docker", "rm", "-f", report["runs"][0]["container_name"]], runner.commands)
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
python -m unittest tests.test_generated_config_runner -v
```

Expected: import failure because `generated_config_runner.py` does not exist.

- [ ] **Step 3: Implement minimal runner**

Implement:

```python
def load_config_slugs(path: Path) -> list[str]: ...
def run_generated_configs(config_slugs, *, timeout_seconds, service="fuzzer-wordpress-plugin", run_command=subprocess.run) -> dict: ...
def write_report(report: Mapping[str, Any], output_file: Path) -> None: ...
def main(argv: Sequence[str] | None = None) -> int: ...
```

Each run command must be:

```python
["docker", "compose", "run", "--rm", "-T", "--name", container_name,
 "-e", f"FUZZER_CONFIG={slug}", service]
```

On `TimeoutExpired`, invoke `run_command(["docker", "rm", "-f", container_name], check=False, capture_output=True, text=True)` and continue. Write output through a sibling temporary file followed by `Path.replace()`.

- [ ] **Step 4: Verify GREEN**

Run the same unittest command. Expected: all tests pass.

### Task 2: Opt-in PowerShell wiring

**Files:**
- Modify: `phuzz-main/code/scripts/wordpress/run-wordpress-phuzz.ps1`
- Modify: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`

- [ ] **Step 1: Write failing wiring contract test**

Read the PowerShell script and assert it contains `RunGeneratedConfigs`, `GeneratedConfigTimeoutSeconds`, a conditional batch branch, `docker compose stop $fuzzerService`, and invocation of `generated_config_runner.py` with summary/output/timeout arguments.

- [ ] **Step 2: Verify RED**

Run:

```powershell
python -m unittest tests.test_generated_config_runner.GeneratedConfigPowerShellContractTests -v
```

Expected: failure because switches and batch invocation are absent.

- [ ] **Step 3: Add minimal PowerShell integration**

Add parameters:

```powershell
[switch]$RunGeneratedConfigs,
[ValidateRange(1, 86400)][int]$GeneratedConfigTimeoutSeconds = 300
```

After conversion, when enabled: stop the default fuzzer, invoke the Python CLI with `generated_config_summary.json`, `generated_config_run_summary.json`, and timeout; throw when CLI exit is non-zero. Skip log following because generated one-off runs have completed. Leave the existing path unchanged when the switch is absent.

- [ ] **Step 4: Verify GREEN**

Run the contract test and the full `test_generated_config_runner` module. Expected: pass.

### Task 3: Documentation and regression verification

**Files:**
- Modify: `phuzz-main/code/docs/guides/hook-aware-seed-generation.md`
- Modify: `phuzz-main/code/scripts/README.md`

- [ ] **Step 1: Document invocation and artifacts**

Document:

```powershell
.\scripts\wordpress\run-wordpress-phuzz.ps1 -RunGeneratedConfigs -GeneratedConfigTimeoutSeconds 300 -NoFollowLogs
```

State that execution is sequential, failures/timeouts are recorded, and output is `fuzzer/output/seed_generation/generated_config_run_summary.json`.

- [ ] **Step 2: Run focused regression tests**

```powershell
python -m unittest tests.test_generated_config_runner tests.test_seed_to_config_exporter -v
```

Expected: all pass.

- [ ] **Step 3: Run full HookPhuzz target suite**

```powershell
python -m unittest tests.test_bootstrap_probe_runner tests.test_entry_classifier tests.test_seed_validator tests.test_bootstrap_entry_discovery tests.test_phuzz_config_writer tests.test_seed_to_config_exporter tests.test_uopz_multistage_metadata_contract tests.test_generated_config_runner -v
```

Expected: all pass.

- [ ] **Step 4: Verify PowerShell syntax and diff**

```powershell
$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path '..\scripts\wordpress\run-wordpress-phuzz.ps1'), [ref]$null, [ref]$errors); if ($errors) { $errors | Format-List; exit 1 }
git diff --check
```

Expected: no parser errors and no whitespace errors.

- [ ] **Step 5: Commit implementation**

```powershell
git add phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py phuzz-main/code/fuzzer/tests/test_generated_config_runner.py phuzz-main/code/scripts/wordpress/run-wordpress-phuzz.ps1 phuzz-main/code/docs/guides/hook-aware-seed-generation.md phuzz-main/code/scripts/README.md phuzz-main/code/docs/superpowers/plans/2026-06-22-generated-config-batch-runner.md
git commit -m "feat: run generated hook configs sequentially"
```

### Task 4: Runtime artifact classification

**Files:**
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_validator.py`
- Modify: `phuzz-main/code/fuzzer/hook_energy/seed_generation/generated_config_runner.py`
- Modify: `phuzz-main/code/fuzzer/tests/test_seed_validator.py`
- Modify: `phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`

- [ ] **Step 1: Write failing validator tests** for `callback_reached`, `registered_not_executed`, `hook_fired_target_not_registered`, `no_artifact`, and `not_observed`; assert no standalone blindspot status.
- [ ] **Step 2: Run `python -m unittest tests.test_seed_validator -v`** and confirm status assertions fail.
- [ ] **Step 3: Expose shared artifact-payload evaluation** in `seed_validator.py`, preserving existing booleans and reasons.
- [ ] **Step 4: Write failing batch tests** asserting elapsed windows are intentional, only new artifacts are evaluated, request counts are recorded, and process failures remain separate.
- [ ] **Step 5: Integrate the batch runner** with complete generated entries and `/shared-tmpfs/hook-coverage/requests` through the `web` service.
- [ ] **Step 6: Run focused and full HookPhuzz suites**, PowerShell parser validation, and `git diff --check`.
