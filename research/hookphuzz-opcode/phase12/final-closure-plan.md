# Phase 12 final closure plan

| Required case | Existing route/test | Existing evidence | Status | Required action |
|---|---|---|---|---|
| Required present/types/path/query/JSON/form/array/object | `items`, `json`, `form` | replay results | covered | retain |
| Required missing, optional states, default origin, enum | existing args | none dedicated | missing | add replays/results |
| Declared unread, no-args, unsupported pattern/object | existing args/routes | capture only | missing evidence | matrix assertions |
| Conflict, wrong callback/ID/stale/location | none | none | missing | verifier cases |
| Multiple endpoints/common args | `methods` | route capture | partial | matrix evidence |
| Runtime-only export block | `runtime` | resolution | partial | negative assertion |
