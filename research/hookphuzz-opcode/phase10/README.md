# HookPhuzz opcode research — Phase 10

Phase 10 is an isolated integration harness. It does not modify Phase 9 or
`phuzz-main/code`; it compiles the frozen Phase 9 extension source unchanged
and consumes HookPhuzz artifacts/config-schema as external contracts. When
live merged evidence is available, `scripts/compat_export.py` imports the
existing `config_exporter.py`; Phase 10 never redefines the PHUZZ wire schema.

## Targets

| Plugin | Version | Entrypoint | Runtime reader |
| --- | --- | --- | --- |
| `hookphuzz-phase10-controlled` | 1.0.0 | `wp_ajax[_nopriv]_hookphuzz_phase10_controlled` | direct superglobals and helper |
| `crm-perks-forms` | 1.0.7 | `wp_ajax_vx_form_save_api_settings` | `cfx_form::post` plus nested `cfx_settings[alert_emails]` |
| `contact-form-7` | 5.7.7 | `rest_route:contact-form-7/v1/contact-forms` | `WP_REST_Request::get_param` |

`targets/contact-form-7.5.7.7.zip` is deliberately not synthesized. Put the
official, pinned plugin archive there before a live run. Its absence is a
documented failed gate, never a pass.

## Run

```bash
bash research/hookphuzz-opcode/phase10/run.sh
```

The command first runs merge-contract tests, then performs bounded Docker
validation. It writes atomically to `results/`:

- `discovery-summary.json`
- `merge-summary.json`
- `generated-config-summary.json`
- `replay-validation-summary.json`
- `phase10-validation-summary.json`
- `final-verdict.txt`, `run.stdout.log`, and `run.exitcode.txt`

The stable parameter identity is `(plugin, entrypoint, root_callback, source,
normalized_path, placement)`. Each merged parameter retains every source of
provenance; same-name reads in another callback, plugin, or REQUEST placement
remain distinct.

The live harness is intentionally fail-closed until all artifact collection and
semantic replay probes are present. It emits `PHASE_10_PASS` only after the
mandatory gate matrix is populated from fresh runtime evidence; otherwise it
prints exact failed gate names. Phase 10 does not run a fuzzing benchmark or
make vulnerability claims.
