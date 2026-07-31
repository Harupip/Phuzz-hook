# HookPhuzz opcode research — Phase 2

## Goal

Copy stable `ZEND_FETCH_DIM_R` operand metadata before dispatch on PHP 8.2.10.

## Run

```bash
bash research/hookphuzz-opcode/phase2/run.sh
```

## Evidence

Read `results/phase2-summary.md` and the generated operand records.

## Boundary

Only direct string/integer keys are copied. No references, conversions,
retained zval pointers, or HTTP-source attribution.
