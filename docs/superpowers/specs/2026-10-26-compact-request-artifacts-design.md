# Compact request artifacts — 2026-10-26

The user authorized reduction after reviewing its tradeoffs, prioritizing discovery results and asking for a durable change record. Use the conservative approach: compact JSON and remove only duplicated per-request blindspot descriptors. The alternative, a registry shared across requests, is deferred because missing or stale references could change discovery results.

Each v4 request retains full registered/executed callback metadata, explicit blindspot IDs, input values, response, correlation identities and runtime/child-hook metadata. Resolve blindspot IDs against registered callbacks in the same request. Aggregate coverage and Zend evidence retain their existing contents. Readers must accept historical v3 requests and preserve validator/registry output; invalid references must report the request and callback ID rather than silently lose evidence.

The existing PHP atomic writer will serialize compact JSON, check encoding/write/rename failures, preserve an existing destination on failure and log the path/reason without logging input values. The replay artifact loader will include the malformed filename in its error. No automatic cleanup, event truncation, registry redesign or Windows checkpoint fix is included.

Record tests, measured bytes, deployment status, compatibility limits and rollback steps in a permanent report. Existing artifacts are immutable. This task does not complete a plugin config, so it must not add checklist rows.
