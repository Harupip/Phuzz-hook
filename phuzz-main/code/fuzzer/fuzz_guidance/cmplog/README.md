# Runtime guard mutations

CMPLOG consumes the completed Zend artifact for the candidate's exact request ID.
Hints only apply to an existing fuzzable parameter with a matching observed value.
Fixed fields and nonce/password/secret/token/auth fields are excluded.

| Runtime evidence | Mutation |
| --- | --- |
| Callback-attributed `empty` access | Replace the parameter with `""`. |
| Callback-attributed `isset` access | Remove the parameter, including when its value is already `""`. |
| Tracked, truthy operand of `BOOL_NOT`, `JMPZ`, or `JMPNZ` | Try `""` and `"0"`. |

`!empty(...)` and `!isset(...)` use the same access evidence as their positive
forms. Removing a query parameter also removes it from the embedded target URL,
so request preparation cannot add it back. Other fields are preserved.
An interesting omission remains in the queue without attempting to freeze a
value that no longer exists. Existing request hashing skips duplicate inputs.

The boolean handler follows existing Zend provenance through assignments and
copies. It ignores constants, unlinked operands, sensitive fields and operands
that are already falsey. `JMPZ`/`JMPNZ` cover conditions whose `BOOL_NOT` is removed
by OPcache optimization. Boolean results do not retain the original input's
provenance. Hints still use normal CMPLOG value and transport matching.

This does not add `TYPE_CHECK`/typed-null mutations, general function-transform
inversion, `strlen`/`count` handling, or parameter/config merging. An unobserved
guard cannot create a hint. `REQUEST`, cookie and REST URL sources retain the
existing fail-closed placement policy. Empty local-variable syntax is not added
as a separate access event.

## Checks

From the fuzzer directory:

```powershell
python -B -m unittest tests.test_cmplog tests.test_cmplog_extension
```

The runtime tests are opt-in and use an already-built extension in a PHP Docker
container. They execute the PHP fixture with OPcache disabled and enabled:

```powershell
$env:HOOKPHUZZ_OPCODE_TEST_CONTAINER = 'code-web-1'
$env:HOOKPHUZZ_OPCODE_TEST_EXTENSION = '/path/to/modules/hookphuzz_opcode.so'
python -B -m unittest tests.test_cmplog_extension.BoolNotRuntimeTests
```

The WordPress launcher rebuilds the web image on the next run. Tests may build
an isolated extension without installing it into the running Apache process.
