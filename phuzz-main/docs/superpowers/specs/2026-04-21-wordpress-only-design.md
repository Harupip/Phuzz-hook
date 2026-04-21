# WordPress-Only PHUZZ Design

**Goal:** Reduce this repo to a WordPress-focused PHUZZ workflow by default, while preserving a safe path to remove the remaining blackbox-tool benchmark pieces later.

## Scope

Phase 1 keeps the core PHUZZ workflow for WordPress and removes benchmark applications that are no longer needed:

- Switch the default compose flow to WordPress.
- Keep `fuzzer`, `web`, `crawler`, `hargen`, and `composegen`.
- Remove bundled benchmark applications and their example configs.
- Keep `burpsuite`, `zap`, `wapiti`, and `wfuzz` on disk for now, but stop treating them as part of the default workflow.

Phase 2 is conditional:

- If the new WordPress-only flow verifies successfully, remove the remaining blackbox-tool benchmark directories and their related docs/experiment references.

## Design

### Runtime defaults

The default `code/docker-compose.yml` should boot a WordPress target plus a PHUZZ container aimed at a WordPress config. The `web` service should set `APPLICATION_TYPE=wordpress`, define `WP_TARGET_PLUGIN`, and scope coverage to the selected plugin path.

### Generation path

`composegen` should generate WordPress-first output by default so future compose files stay aligned with the simplified repo. The generated template should no longer include the blackbox-tool services in phase 1.

### Repo trimming

The following benchmark-only assets should be removed in phase 1:

- `code/web/applications/bwapp`
- `code/web/applications/dvwa`
- `code/web/applications/testsuite`
- `code/web/applications/wackopicko`
- `code/web/applications/xvwa`
- matching directories under `code/fuzzer/configs`
- benchmark-only login scripts in `code/fuzzer/automated_logins`

### Documentation

Top-level and `code/` docs should describe the repo as WordPress-first and show the default run path against WordPress only. Any remaining benchmark language should either be removed or clearly marked as historical context.

## Risks and mitigations

- The WordPress plugin zips are still ignored from git, so verification may be limited by whether local plugin archives are present.
- Some WordPress configs contain captured cookies from historical experiments; these can remain for phase 1 because the repo simplification is structural, not a full config normalization pass.
- Because this workspace is not a git worktree, the usual "commit the spec" step is not available here. The spec is still written to disk for traceability.
