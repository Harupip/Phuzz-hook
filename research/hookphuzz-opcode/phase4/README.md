# HookPhuzz opcode research — Phase 4

Phase 4 is an isolated PHP 8.2.10 CLI experiment for dynamic request-parameter discovery in direct, read-only request access. It adds common silent reads to the Phase 3 normal-read coverage without implementing taint tracking or request-value transport.

Run from the repository root:

```bash
bash research/hookphuzz-opcode/phase4/run.sh
```

## Registered opcode scope

The extension registers only `ZEND_FETCH_R`, `ZEND_FETCH_DIM_R`, `ZEND_FETCH_IS`, `ZEND_FETCH_DIM_IS`, and `ZEND_ISSET_ISEMPTY_DIM_OBJ`.

- `FETCH_R` / `FETCH_DIM_R` preserve Phase 3 normal reads and emit `access_context: "read"`.
- `FETCH_IS` accepts only global, constant `_GET`, `_POST`, `_REQUEST`, and `_COOKIE` roots.
- `FETCH_DIM_IS` emits `access_context: "silent_read"`; that opcode alone cannot prove coalesce versus an intermediate nested silent access.
- `ISSET_ISEMPTY_DIM_OBJ` uses `ZEND_ISEMPTY` metadata to emit exact `isset` or `empty` context.

No write, reference, assignment, function-transport, property, ArrayAccess, or variable-variable provenance is registered. The PHP 8.2 user-code function-call end observer only releases records belonging to a completed execute frame; it emits no access events.

## Provenance and events

Provenance is request-local metadata keyed by `(execute frame, result.var)` and contains only a source (`GET`, `POST`, `REQUEST`, `COOKIE`) plus copied observed string/integer path keys. No zval pointer or request value is retained or exported. The frame-end observer removes completed-frame provenance and request shutdown releases all remaining events/metadata.

Each mapped dimension event remains `superglobal_dim_read` and includes `source`, `path`, `opcode`, `access_context`, key metadata, file, and line. String keys are parameter candidates; integer keys remain mapped but are not candidates. Unsupported key types produce only an unmapped event and are never converted or coerced.

## Coverage and guarantees

The fixture suite proves literal/runtime coalesce, isset, empty, nested paths, and exact GET/POST/REQUEST/COOKIE attribution. It also proves zero mapped events for local arrays, fake/lowercase globals, object/static properties, ArrayAccess, parameters, and variable variables. Phase 3 direct-read cases are copied as Phase 4 regressions.

The runner compares extension OFF and ON stdout, stderr, exit code, warnings/notices, caught exception class/message, and a `__toString` counter. It verifies the 4096-event cap and drop count, request reset, repeated calls, recursion, and 400 bounded PHP processes. Every user-opcode handler returns `ZEND_USER_OPCODE_DISPATCH` and does not modify PHP operands, results, warnings, exceptions, output, or exit status.

## Limits and deferred scope

Phase 4 proves direct opcode-slot provenance only. It deliberately excludes assignment aliases, references, function arguments/returns, helper discovery, properties, ArrayAccess, variable variables, `filter_input`, JSON body, WordPress/REST, UOPZ, HookPhuzz artifact/config integration, replay, and complete dynamic parameter discovery.
