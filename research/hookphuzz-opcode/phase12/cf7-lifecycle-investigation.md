# Phase 12 CF7 lifecycle investigation

Phase 12 owns `hookphuzz-phase12`, which runs the fixture. Its runner then copied the CF7 replay script into the literal container `phase11b-cf7-web-1`. That container belongs to the distinct `phase11b-cf7` Compose project and is removed or stopped by the Phase 11B runner's cleanup trap.

The literal name is not a valid dependency: Compose project naming and container numbering are runtime details. The reusable Phase 11B assets are its Compose file, Dockerfile, WordPress setup script, CF7 observer, and authenticated replay environment. Phase 12 must start that stack with the same environment variables, wait for it to be ready, discover the single `web` service container through Compose, and scope cleanup to that project.

The minimal repair is a shared lifecycle helper used by Phase 11B and Phase 12. It owns stack startup, bounded readiness checks, dynamic service discovery, machine-readable bootstrap evidence, and scoped cleanup. Phase 12 keeps its own fixture flow and its existing CF7 replay script.
