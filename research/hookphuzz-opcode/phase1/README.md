# HookPhuzz opcode research — Phase 1

Phase 1 proves that a small PHP C extension can register a user opcode handler for `ZEND_FETCH_DIM_R`, count runtime invocations per request, and dispatch execution back to Zend's original handler.

It does not read operands, keys, compiled variables, runtime values, or superglobals. It does not identify HTTP parameters, export JSON, integrate WordPress/UOPZ/HookPhuzz, or prove dynamic parameter discovery.

## Run

With Docker Desktop running:

```bash
bash research/hookphuzz-opcode/phase1/run.sh
```

The runner builds the isolated `php:8.2.10-cli` image, enables the extension, runs the checks with OPcache CLI and JIT disabled, and writes real command evidence to `results/`.

## Results

`results/phase1-summary.md` gives the final status. The counter tests show handler invocation only: they do not establish which array/key/value was read, or whether it came from an HTTP parameter.
