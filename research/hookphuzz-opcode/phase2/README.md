# HookPhuzz opcode research — Phase 2

Phase 2 records request-local metadata for `ZEND_FETCH_DIM_R` only on PHP 8.2.10. The extension observes `op1` and `op2` using `zend_get_zval_ptr()`, copies stable metadata before dispatch, and always returns `ZEND_USER_OPCODE_DISPATCH`.

## Run

With Docker Desktop running:

```bash
bash research/hookphuzz-opcode/phase2/run.sh
```

The runner builds an isolated `php:8.2.10-cli` image, disables OPcache CLI and JIT in all semantic checks, and writes command evidence to `results/`.

## Operand resolution

PHP 8.2.10 implements `zend_get_zval_ptr()` as follows:

- `IS_CONST`: `RT_CONSTANT(opline, *node)`.
- `IS_CV`, `IS_TMP_VAR`, `IS_VAR`: `EX_VAR(node->var)`.
- Other operand types: `NULL` / unavailable.

The extension stores only zval type for containers and non-string/non-integer keys. It copies a key only when its direct zval type is `IS_STRING` or `IS_LONG`; it does not dereference references, stringify values, invoke conversions, or retain zval pointers.

## Non-goals

This prototype does not identify `$_POST`, `$_GET`, `$_REQUEST`, or `$_COOKIE`; track `FETCH_R` provenance; map keys to HTTP parameters; export extension JSON to the filesystem; run inside WordPress; integrate HookPhuzz; or establish nested HTTP provenance. A nested event sequence is only an opcode sequence.
