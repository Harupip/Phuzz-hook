# HookPhuzz opcode research — Phase 0

This isolated workspace verifies how PHP 8.2 compiles request-array reads before any `hookphuzz_opcode` extension is written. It neither loads UOPZ nor connects to WordPress or the HookPhuzz pipeline.

## Run

Start Docker Desktop, then run from Git Bash, or from WSL only after enabling Docker Desktop's WSL integration:

```bash
./research/hookphuzz-opcode/phase0/run.sh
```

The runner first builds and uses VLD. If that build fails, it preserves the real error in `results/vld-build.log` and retries with PHP's OPcache debug dump on the same `php:8.2.10-cli` image. Only if that exact image cannot build does it retry the maintained `php:8.2-cli` tag. The selected image's real PHP version is recorded in `results/environment.txt`.

Equivalent explicit command for the VLD path:

```bash
docker compose -p hookphuzz-opcode-phase0 -f research/hookphuzz-opcode/phase0/docker-compose.yml build phase0-vld
docker compose -p hookphuzz-opcode-phase0 -f research/hookphuzz-opcode/phase0/docker-compose.yml run --rm phase0-vld
```

## Evidence

- `results/raw-opcodes.txt`: unmodified opcode-dumper output.
- `results/environment.txt`: PHP version, enabled modules, OPcache/JIT settings, and selected dumper.
- `results/runtime-semantics.txt`: captured missing-key warning and return-value behavior.
- `results/vld-build.log`: VLD build output, including the fallback reason when applicable.
- `results/opcode-summary.md`: analyst-written mapping and operand analysis derived only from `raw-opcodes.txt` after a successful run.

Phase 0 passes only when the raw output covers every case in `opcode_cases.php`, identifies the dynamic-key operand and nested chain, and the runtime file records the four required missing-key semantics. Until then, no C extension, opcode handler, operand reader, superglobal recognition, or JSON export is justified.
