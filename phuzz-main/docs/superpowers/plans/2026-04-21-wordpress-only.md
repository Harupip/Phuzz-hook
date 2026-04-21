# WordPress-Only PHUZZ Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the repo WordPress-only by default, remove benchmark applications/configs, and verify the simplified flow before considering a second cleanup pass.

**Architecture:** Keep the existing PHUZZ core intact and narrow the default runtime surface area around WordPress. Update compose generation first so new files stay aligned, then trim benchmark data and refresh docs to match the new default.

**Tech Stack:** Docker Compose, Python, PHP, shell scripts, Markdown

---

### Task 1: Record the design and scope

**Files:**
- Create: `docs/superpowers/specs/2026-04-21-wordpress-only-design.md`
- Create: `docs/superpowers/plans/2026-04-21-wordpress-only.md`

- [ ] **Step 1: Write the design spec**

Create the spec file describing the phase 1 and phase 2 boundaries, runtime defaults, repo trimming list, and verification caveats.

- [ ] **Step 2: Write the implementation plan**

Create this plan file so the simplification work has an explicit sequence.

### Task 2: Make runtime defaults WordPress-first

**Files:**
- Modify: `code/docker-compose.yml`
- Modify: `code/composegen/composegen.py`
- Modify: `code/composegen/composegen.sh`
- Modify: `code/composegen/README.md`

- [ ] **Step 1: Change the checked-in compose defaults**

Set the `web` service to `APPLICATION_TYPE=wordpress`, add `WP_TARGET_PLUGIN`, point the default fuzzer at a WordPress config, and scope coverage to the selected plugin path.

- [ ] **Step 2: Update compose generation defaults**

Change `composegen.py` and the sample shell wrapper so generated compose files default to WordPress and omit the blackbox-tool services from the generated template.

- [ ] **Step 3: Refresh composegen docs**

Update the README examples so the documented generation path matches the new WordPress-only default.

### Task 3: Remove benchmark application payloads

**Files:**
- Delete: `code/web/applications/bwapp`
- Delete: `code/web/applications/dvwa`
- Delete: `code/web/applications/testsuite`
- Delete: `code/web/applications/wackopicko`
- Delete: `code/web/applications/xvwa`
- Delete: `code/fuzzer/configs/bwapp`
- Delete: `code/fuzzer/configs/dvwa`
- Delete: `code/fuzzer/configs/testsuite`
- Delete: `code/fuzzer/configs/wackopicko`
- Delete: `code/fuzzer/configs/xvwa`
- Delete: `code/fuzzer/automated_logins/dvwa_requests.py`
- Delete: `code/fuzzer/automated_logins/wackopicko_requests.py`

- [ ] **Step 1: Remove benchmark web applications**

Delete the benchmark application directories that are no longer part of the WordPress-only repo.

- [ ] **Step 2: Remove benchmark PHUZZ configs**

Delete the matching benchmark config directories so the fuzzer config tree only contains WordPress examples after phase 1.

- [ ] **Step 3: Remove benchmark-only login helpers**

Delete the login scripts that only supported the removed benchmark apps.

### Task 4: Refresh docs to match the simplified repo

**Files:**
- Modify: `README.md`
- Modify: `code/README.md`
- Modify: `code/web/README.md`
- Modify: `code/fuzzer/configs/README.md`
- Modify: `code/fuzzer/automated_logins/README.md`
- Modify: `experiments/README.md`

- [ ] **Step 1: Rewrite top-level positioning**

Describe the checked-in repo as WordPress-only by default and move cross-target benchmark language into historical context.

- [ ] **Step 2: Rewrite the run instructions**

Show the default path as bringing up WordPress and a WordPress PHUZZ container.

- [ ] **Step 3: Remove stale benchmark references**

Update the remaining docs so they do not promise deleted directories or deleted login scripts.

### Task 5: Verify and decide on phase 2

**Files:**
- Modify: none required unless verification finds issues

- [ ] **Step 1: Run syntax checks for the changed Python**

Run: `python -m py_compile code/composegen/composegen.py`

Expected: exit code 0 and no traceback.

- [ ] **Step 2: Generate a fresh compose file**

Run: `python code/composegen/composegen.py --output-dir code/composegen --configs wordpress/show-all-comments-in-one-page:1 --application-type wordpress --coverage-path wp-content/plugins/show-all-comments-in-one-page`

Expected: the generated file targets WordPress and contains only the PHUZZ-oriented services.

- [ ] **Step 3: Inspect the generated compose file**

Run: `Get-Content code/composegen/docker-compose.yml`

Expected: `APPLICATION_TYPE: wordpress`, `WP_TARGET_PLUGIN: show-all-comments-in-one-page`, and no `burpsuite`, `zap`, `wapiti`, or `wfuzz` services.

- [ ] **Step 4: If plugin archives are present, try the lightweight container bring-up**

Run: `docker compose -f code/docker-compose.yml config`

Expected: compose parses successfully.

- [ ] **Step 5: Use the verification result to decide phase 2**

If the WordPress-only flow verifies cleanly, proceed to remove the remaining blackbox-tool directories and their docs references in a second pass.
