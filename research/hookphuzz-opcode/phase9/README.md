# HookPhuzz opcode research — Phase 9

Phase 9 hands registered callback targets from a UOPZ discovery request to the opcode extension on the next request. The handoff is intentionally two-request: WordPress plugin registration writes `/shared/phase9-callback-registry.json` at PHP shutdown; the extension reads its completed atomic snapshot at the following RINIT.

`hookphuzz_opcode.target_callbacks_file` is parsed on every request. Static `hookphuzz_opcode.target_callbacks` and file targets are unioned case-insensitively. Registry schema is version 1; artifact schema is version 3. Limits are 1 MiB registry input, 256 targets, and 255 callback bytes. Missing, empty, malformed, unsupported, and partially valid input only affects `target_loading` in the artifact.

The MU-plugin hooks `add_action` and `add_filter` through UOPZ. It admits registrations whose call stack originates under the Phase 9 fixture directory, so ordinary WordPress bootstrap callbacks remain raw unattributed noise. It stores only hook/callback metadata; closures are diagnostics and never stable targets.

Run from repository root:

```bash
bash research/hookphuzz-opcode/phase9/run.sh
```

If Docker Desktop builds run through a TLS-intercepting proxy, provide its
trusted root certificate so BuildKit can verify WordPress and WP-CLI downloads:

```bash
export HOOKPHUZZ_BUILD_CA_FILE=/path/to/proxy-root-ca.crt
bash research/hookphuzz-opcode/phase9/run.sh
```

The certificate is passed as a BuildKit secret and is not copied into the
image. Without it, the runner fails closed at Docker build time.

## Status

`PHASE_9_PASS` was recorded by the clean run `phase9-20260720T183318Z-7402` with runner exit status 0. Evidence: `results/phase9-validation-summary.json`, `results/replay-validation-summary.json`, `results/concurrency-summary.json`, and `results/stability-summary.json`.

Deferred: PHUZZ mutation, hook energy/scoring, vulnerability detection, taint/propagation/sinks, non-AJAX entrypoints, real-plugin validation, and benchmarking.
