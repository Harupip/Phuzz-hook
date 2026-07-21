# HookPhuzz opcode research — Phase 6

Phase 6 is an isolated WordPress compatibility and request-noise proof for the Phase 5 direct-superglobal opcode extension. It runs PHP 8.2.10 through Apache/mod_php with WordPress 6.5.5, MariaDB 10.11.8, OPcache disabled, JIT disabled, and no UOPZ.

Run from the repository root:

```bash
bash research/hookphuzz-opcode/phase6/run.sh
```

The enabled and disabled WordPress stacks use independent databases and filesystems. The enabled stack builds `extension/` locally; it does not load Phase 0–5 at runtime. The fixture exposes `wp_ajax_nopriv_hookphuzz_phase6_probe` and makes only the specified direct GET/POST/REQUEST/COOKIE reads.

Artifacts contain direct source/path/operation metadata, request ID, PID, method, and a redacted URI. They intentionally do not contain request values. `tests/run.sh` uses the fixture’s unique runtime key and raw response evidence to verify request isolation, then reports WordPress bootstrap noise by event order and fixture file/function identity. That analysis is not callback-context attribution.

Missing, invalid, and duplicate `X-Fuzzer-Covid` IDs retain the Phase 5 policy: no artifact for missing/invalid IDs and no overwrite for duplicates. Raw artifacts, responses, headers, and logs remain in `results/raw-enabled/` and `results/raw-disabled/` even when a gate fails.

Phase 6 excludes helper propagation, assignment/argument/return/property provenance, complete dynamic discovery, PHUZZ/HookPhuzz pipeline work, UOPZ, config generation, replay generation, and Phase 7.
