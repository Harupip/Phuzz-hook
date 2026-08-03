# Implementation plan

1. Fresh Phase 12 baseline.
2. Independently activate each pinned ZIP in a scoped Compose project and capture its runtime REST registry.
3. Normalize plugin-owned route-method records, generate only supported configs through production code, replay benign public and authenticated routes, then fail closed on current-run gates.
