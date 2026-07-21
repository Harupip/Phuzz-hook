# HookPhuzz opcode research — Phase 8

Phase 8 hands registered callback targets from a UOPZ discovery request to the opcode extension on the next request. The handoff is intentionally two-request: WordPress plugin registration writes `/shared/phase8-callback-registry.json` at PHP shutdown; the extension reads its completed atomic snapshot at the following RINIT.

`hookphuzz_opcode.target_callbacks_file` is parsed on every request. Static `hookphuzz_opcode.target_callbacks` and file targets are unioned case-insensitively. Registry schema is version 1; artifact schema is version 3. Limits are 1 MiB registry input, 256 targets, and 255 callback bytes. Missing, empty, malformed, unsupported, and partially valid input only affects `target_loading` in the artifact.

The MU-plugin hooks `add_action` and `add_filter` through UOPZ. It admits registrations whose call stack originates under the Phase 8 fixture directory, so ordinary WordPress bootstrap callbacks remain raw unattributed noise. It stores only hook/callback metadata; closures are diagnostics and never stable targets.

Run from repository root:

```bash
bash research/hookphuzz-opcode/phase8/run.sh
```

Read `results/final-report.md` and linked JSON evidence. Deferred: PHUZZ config/replay, hook energy, fuzzing, vulnerability detection, taint/propagation/sinks, request generation, and benchmarking.
