# Phase 11 REST Method Generalization

Runs an isolated WordPress 6.5.5/PHP 8.2.10/UOPZ fixture. It proves actual REST
dispatch and fixture-side request-ID evidence for GET, POST, PUT, PATCH, DELETE,
and both variants of a PUT/PATCH declaration.

```bash
bash research/hookphuzz-opcode/phase11-rest-method-generalization/run.sh
```

The runner moves prior results into `results/history/` before starting, then
only accepts callback artifacts named with the current request IDs. Phase 11B
is deliberately blocked pending an independently reproducible real-plugin
route that does not require an expanded authentication test framework.
