# HookPhuzz opcode research — Phase 3

Phase 3 is an isolated PHP 8.2.10 CLI experiment. Run it with Docker Desktop:

```bash
bash research/hookphuzz-opcode/phase3/run.sh
```

## Provenance

Provenance is request-local metadata stating that a temporary result slot came from one exact HTTP superglobal: `$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE`. It is not a zval pointer and is not a value copy.

`ZEND_FETCH_R (global)` is accepted only when its constant `op1` is one of `_GET`, `_POST`, `_REQUEST`, or `_COOKIE` and the opcode has the PHP global-fetch flag. The extension records the source, active execute-frame identity, result `var` offset, and an empty path.

On `ZEND_FETCH_DIM_R`, the extension checks whether its container operand is a tracked result slot. It copies only direct string or integer keys, emits a `superglobal_dim_read` event, appends that key to a new path, and associates the new path with the dimension-read result slot. Therefore `$_POST['user']['name']` yields paths `['user']` then `['user', 'name']`.

Only string keys are `parameter_candidate: true`. Integer keys are mapped but false. Unsupported keys are reported with `mapped: false` and `unsupported_key_type`; no string conversion, `__toString`, userland callback, or zval-pointer retention occurs.

## Meaning and limits

Nested paths prove direct opcode-slot provenance, not a complete model of HTTP nested parameters. Phase 3 intentionally does not track assignment aliases, references, helpers, function parameter passing, object-property transport, ArrayAccess, variable variables, WordPress REST request objects, WordPress containers, HookPhuzz exports/configs, or complete dynamic parameter discovery.

Handlers observe request-local metadata only, never alter the opline, operands, result zval, symbol table, warnings, returns, or filesystem. Both handlers always return `ZEND_USER_OPCODE_DISPATCH`. JSON is produced by test fixtures after opcode execution. Metadata and copied strings are released at request shutdown; event storage is capped at 4096 with a dropped-event counter.
