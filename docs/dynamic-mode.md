# Dynamic parameter discovery

`phuzz.ps1 -Mode dynamic` is an opt-in workflow for **runtime-guided, source-assisted** parameter discovery. It does not treat every runtime string passed to a helper as an HTTP parameter.

## Run

From `phuzz-main/code`:

```powershell
.\phuzz.ps1 -Mode dynamic -PluginSlug crm-perks-forms -NoFollowLogs
```

Useful options:

```powershell
.\phuzz.ps1 -Mode dynamic -PluginSlug crm-perks-forms `
  -WebTimeoutSeconds 240 `
  -SeedWaitSeconds 45 `
  -GeneratedConfigTimeoutSeconds 30 `
  -NoFollowLogs
```

`dynamic` always delegates with `ParamDiscoveryMode=dynamic-helper` and `RunGeneratedConfigs`. The plugin needs a ZIP at `web/applications/wordpress/_plugins/<slug>.zip`; it does not need a static bootstrap config.

## Workflow

1. Dynamic output/config roots for the selected plugin are cleared. Static roots are not touched.
2. The runner copies plugin source from the web container and runs `HelperRequestReaderAnalyzer`.
3. Only high-confidence helpers with source proof that an argument indexes a supported HTTP source are published to the container. Example: `cfx_form::post($key) -> $_REQUEST[$key]`.
4. Normal hook seed export creates an initial dynamic config set.
5. A **discovery replay** runs that initial set. UOPZ records a helper argument only while a registered target callback is active.
6. New request artifacts are copied back. Trusted observations merge into the separate dynamic configs; duplicate observations are coalesced into `observation_count`.
7. A **final replay** runs every merged dynamic config. Only this pass decides E2E status.

The generated-config runner receives the temporary Compose override through `COMPOSE_FILE`; dynamic environment variables stay active in both replay passes.

## Trust boundary

An observation becomes a fuzzing candidate only when all conditions hold:

- The helper registry source-proves request-reader semantics.
- UOPZ observes the helper inside the expected callback.
- Callback id, entrypoint, HTTP source, parameter path, schema, and confidence validate during merge.

Direct superglobal reads and arbitrary helper strings are not promoted by this workflow. Observed values are not collected.

`merge_action=matched_existing` is valid: dynamic evidence proved a parent/path already covered by a static selector, so no duplicate selector is added. For example, runtime `cfx_settings` matches static `cfx_settings[alert_emails]`.

## Output

Dynamic runs use only these roots:

```text
fuzzer/output/param-discovery/<plugin>/dynamic-helper/
fuzzer/configs/generated-param-discovery/<plugin>/dynamic-helper/
```

Important output files:

| File | Meaning |
| --- | --- |
| `helper_reader_registry.json` | Source-proven readers and rejected source candidates. |
| `runtime_discovery_summary.json` | Copied request artifact count, observations, observed helpers, and reader-hook debug states. |
| `generated_config_summary.json` | Generated/skipped final dynamic configs. |
| `generated_param_summary.json` | Parameter provenance and merge actions. |
| `dynamic_discovery_run_summary.json` | First replay used to collect runtime evidence; not the E2E verdict. |
| `dynamic_discovery_validation_result.json` | Callback validation for discovery replay. |
| `generated_config_run_summary.json` | Final replay process and callback results. |
| `validation_result.json` | Final callback validation; E2E source of truth. |

## E2E result

The command reports `Dynamic E2E PASS` only when every final generated config has `callback_reached=true`.

It fails when no configs are generated, a replay errors/times out, or any final validation is `registered_not_executed`, `hook_fired_target_not_registered`, `no_artifact`, or `not_observed`.

The discovery replay may contain misses; it supplies evidence only. The final replay remains the pass/fail gate.

## Troubleshooting

- `runtime_symbol_not_defined`: the helper class was unavailable during bootstrap. Dynamic mode retries reader-hook installation once at the first registered target callback, after that callback has loaded its symbol.
- `merge_action=matched_existing`: expected when static extraction already fuzzes the discovered path or a child path.
- `runtime_observations=0`: inspect `helper_reader_registry.json`, `runtime_discovery_summary.json`, and `dynamic_discovery_validation_result.json`; no runtime parameter is trusted without an observed target callback.
