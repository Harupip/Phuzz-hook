# Phase 12 lifecycle handoff

Starting commit: `4da0107da10bbe0985ed3830bdfd6ce458b3c00b`.

The initial scoped diff changed the Phase 11B runner to call a new shared CF7
lifecycle helper; changed Phase 12 to create per-run results, bootstrap CF7,
and use a discovered container ID; and added current-run artifact and redaction
support. The audit patch is stored in
`results/phase12-handoff-20260802T125000Z/starting-lifecycle-diff.patch`.

Retained work: shared helper extraction, per-run result directories, dynamic
container intent, scoped cleanup intent, and replay redaction markers.

Incomplete work corrected here: canonical repository resolution, unique Compose
project identity, Dockerfile COPY validation, label validation, bounded failure
diagnostics, lifecycle command tests, and current-run artifact validation.

The original literal `phase11b-cf7-web-1` dependency was removed from the Phase
12 runner. The historical forced-stop investigation found `OOMKilled=false`;
exit 137 followed the configured `SIGWINCH` stop signal.
