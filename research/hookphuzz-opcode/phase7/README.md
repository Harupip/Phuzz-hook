# HookPhuzz opcode research — Phase 7

Phase 7 attributes Phase 6 direct `$_GET`, `$_POST`, `$_REQUEST`, and `$_COOKIE` reads to configured WordPress callbacks. Request-level discovery records every read in a request; callback attribution keeps those raw events but identifies which reads execute in a target callback or its userland helpers.

The PHP 8.2.10 extension uses Zend observer function `begin`/`end` handlers. A configured callback starts a request-local root frame at depth 0. Userland helpers inherit that root and increase depth. End handlers pop matching frames; RSHUTDOWN releases any remaining request-local state.

Configure roots through the PHP INI directive:

```ini
hookphuzz_opcode.target_callbacks=hookphuzz_phase7_probe,HookPhuzz_Phase7_Handler::probe
```

Artifacts use schema version 2. Each direct-read event retains Phase 6 fields plus `callback_context` with `attributed`, `root_callback`, `current_function`, and `depth`. `callback_summaries` are derived from accepted attributed events. Request values are never recorded.

Run from the repository root:

```bash
bash research/hookphuzz-opcode/phase7/run.sh
```

Read `results/final-report.md` first, then its JSON evidence and `sample-artifacts/`. The runner builds clean isolated enabled/disabled WordPress stacks, keeps OPcache/JIT disabled, and exits non-zero on any failed gate.

Known limitation: closure labels are diagnostic only. Deferred: PHUZZ/config/replay/UOPZ integration, callback discovery, propagation/taint analysis, vulnerability detection, hook energy, and benchmarks.
