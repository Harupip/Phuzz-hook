# Generated Config Batch Runner Design

## Goal

Add an opt-in `-RunGeneratedConfigs` mode to the WordPress PHUZZ runner. The mode must execute generated hook configs sequentially within a bounded run window, validate target callbacks from new request artifacts, and write a machine-readable run summary.

## Scope

- Preserve current behavior when `-RunGeneratedConfigs` is absent.
- Keep the existing default fuzzer run long enough to produce hook coverage.
- Export `suggested_seeds.json` and convert supported seeds into `configs/generated-hooks/*.json`.
- Stop the default fuzzer before starting generated config runs.
- Run every `generated[].config_slug` from `generated_config_summary.json` once.
- Record process outcome, new request count, and callback validation status for every attempted config.

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
5. Treats run-window expiry as intentional cleanup, not a fuzzing failure.
6. Evaluates only request artifacts created during that config's run window.
7. Writes `generated_config_run_summary.json` atomically after the batch finishes.

Container names use the config index plus a sanitized slug to avoid invalid Docker names.

## Output

The run summary contains:

- `generated_config_summary`: source summary path.
- `timeout_seconds`: configured timeout.
- `runs`: ordered rows with config identity, process outcome, validation status, request count, exit code, duration, and container name.
- `counts`: totals grouped by validation status.

Validation status precedence is:

1. `callback_reached`: target exists in `executed_callbacks`.
2. `registered_not_executed`: target exists in `registered_callbacks` but not `executed_callbacks`.
3. `hook_fired_target_not_registered`: target hook fired but target callback was not registered.
4. `no_artifact`: the run created no request artifact.
5. `not_observed`: artifacts exist but neither target hook nor callback was observed.

`blindspot_callbacks` remains metadata, not a separate status, because instrumentation derives it from active registered callbacks absent from `executed_callbacks`. Exit code is `0` only when every target is `callback_reached`, `1` for any other runtime result, and `2` for invalid input.

## Error Handling

- Missing/malformed summary: fail before Docker execution.
- Empty generated list: write an empty successful summary.
- Non-zero Docker exit before window end: record process failure, continue.
- Run window elapsed: force-remove named container, validate new artifacts, continue.
- Summary write failure: fail loudly.

## Tests

Python unit tests cover:

- Ordered execution and successful summary counts.
- Non-zero exit handling without stopping later configs.
- Run-window cleanup and continued execution.
- Validation precedence from new request artifacts.
- Missing or malformed generated config entries.
- CLI output and exit codes.

PowerShell receives only narrow wiring changes; Python tests verify deterministic batch behavior without requiring Docker.
