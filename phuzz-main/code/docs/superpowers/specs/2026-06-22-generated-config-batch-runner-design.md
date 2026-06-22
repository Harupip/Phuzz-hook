# Generated Config Batch Runner Design

## Goal

Add an opt-in `-RunGeneratedConfigs` mode to the WordPress PHUZZ runner. The mode must execute generated hook configs sequentially with a per-config timeout and write a machine-readable run summary.

## Scope

- Preserve current behavior when `-RunGeneratedConfigs` is absent.
- Keep the existing default fuzzer run long enough to produce hook coverage.
- Export `suggested_seeds.json` and convert supported seeds into `configs/generated-hooks/*.json`.
- Stop the default fuzzer before starting generated config runs.
- Run every `generated[].config_slug` from `generated_config_summary.json` once.
- Record `passed`, `failed`, or `timed_out` for every attempted config.

REST, shortcode, rewrite, XML-RPC setup, recursive child-hook generation, login automation, retries, and parallel runs remain out of scope.

## Interface

`scripts/wordpress/run-wordpress-phuzz.ps1` gains:

- `-RunGeneratedConfigs`: enables batch execution.
- `-GeneratedConfigTimeoutSeconds`: positive per-config timeout; default 300 seconds.

Without the switch, the script retains the current log-following behavior.

## Components

### PowerShell orchestration

After seed conversion, the PowerShell runner stops `fuzzer-wordpress-plugin` and invokes a small Python batch CLI. PowerShell remains responsible for Docker/bootstrap lifecycle only.

### Python batch CLI

`hook_energy/seed_generation/generated_config_runner.py`:

1. Reads `generated_config_summary.json`.
2. Validates its `generated` list and positive timeout.
3. Runs configs sequentially using:

   `docker compose run --rm -T --name <unique-name> -e FUZZER_CONFIG=<slug> fuzzer-wordpress-plugin`

4. Assigns an explicit container name so timeout cleanup can run `docker rm -f <name>`.
5. Continues after failure or timeout.
6. Writes `generated_config_run_summary.json` atomically after the batch finishes.

Container names use the config index plus a sanitized slug to avoid invalid Docker names.

## Output

The run summary contains:

- `generated_config_summary`: source summary path.
- `timeout_seconds`: configured timeout.
- `runs`: ordered rows with `config_slug`, `status`, `exit_code`, `duration_seconds`, and `container_name`.
- `counts`: `total`, `passed`, `failed`, and `timed_out`.

Exit code is `0` when every run passes, `1` when any run fails or times out, and `2` for invalid CLI input or malformed summary data.

## Error Handling

- Missing/malformed summary: fail before Docker execution.
- Empty generated list: write an empty successful summary.
- Non-zero Docker exit: record `failed`, continue.
- Timeout: force-remove named container, record `timed_out`, continue.
- Summary write failure: fail loudly.

## Tests

Python unit tests cover:

- Ordered execution and successful summary counts.
- Non-zero exit handling without stopping later configs.
- Timeout cleanup and continued execution.
- Missing or malformed generated config entries.
- CLI output and exit codes.

PowerShell receives only narrow wiring changes; Python tests verify deterministic batch behavior without requiring Docker.
