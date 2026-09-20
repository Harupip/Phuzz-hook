# Online-linked only Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline.

**Goal:** Keep online-linked as the only supported WordPress workflow.
**Architecture:** Remove public mode dispatch and exclusive legacy orchestration. Keep the shared replay runner, Zend bridge, exporters and worker runtime used by online-linked.
**Tech Stack:** PowerShell, Python unittest, Docker Compose.
**Spec:** User instruction in this task: "Chỉ giữ mỗi online-linked thôi bỏ hết mode còn lại".

## Global Constraints

- Work on feature/separate-online-linked; preserve the existing extraction and unrelated WIP. No staging, commit or push requested.
- Remove default, seed-config, generated, zend and online workflows and their exclusive switches/tests. Keep historical reports and user configs.
- Default to online-linked; keep explicit -Mode online-linked accepted. Enable required Zend discovery automatically. Retain -UseZendDiscovery for existing linked commands. Remove direct runner -RunOnlineLinked to prevent PowerShell accepting retired -RunOnline as its abbreviation.
- Keep normal plugin selection when invoked without arguments; explicit plugin or dry-run must not prompt.
- Keep shared library entrypoints and tests even when their names mention generated or Zend.

## Review Focus

- Old modes must fail before invoking Docker.
- Default noninteractive invocation must reach linked launch with Zend enabled.
- Env overrides and CLI precedence must survive.
- Bootstrap, callback registry, auth and nonce seed paths must use the campaign snapshot.
- Removing old tests must not remove coverage of retained shared functions.

### Task 1: Remove legacy workflow surfaces and exclusive implementation

**Files:** phuzz.ps1; scripts/wordpress/run-wordpress-phuzz.ps1; read-phuzz-env.ps1; phuzz.env; fuzzer/hook_energy/seed_generation/online_config_runner.py; wrapper, generated runner and old online tests.
**Interfaces:** Existing Invoke-OnlineLinked arguments stay unchanged. online_common.select_v0 and generated_config_runner stay available.

- [x] Add runnable PowerShell tests for rejection of five old modes, default linked dry-run, and obsolete parameter rejection; run and observe failures.
- [x] Remove old CLI/menu branches, unused generated/Zend options and old online coordinator. Remove exclusive wrapper functions after caller audit; simplify export to runtime Zend seeds.
- [x] Migrate shared v0 validation/bootstrap tests to online_common; remove only old orchestration test cases. Run wrapper/package/replay tests.

### Task 2: Document and verify the remaining workflow

- [x] Update current user guides and scripts README; mark old mode guides historical without rewriting old reports.
- [x] Run full explicit-module unittest suite (bounded, PHP test ini workaround as documented in extraction report), diff checks, caller audit and WIP hashes.
- [x] Run bounded public-wrapper Docker smoke; use short scratch roots for full replay/Pass2 proof if the known Windows path limit blocks default roots. Report the distinction.
- [x] Review the whole change directly; fix material findings and rerun affected checks.

## Execution rulings

- User explicitly authorized removal after the scope discussion; proceed without another plan approval.
- No commit steps: preserve user control over the mixed uncommitted workspace.
- User requested no sub-agents; the review agent was interrupted immediately. Complete review directly.
- Direct-runner regression exposed PowerShell abbreviation: -RunOnline bound to -RunOnlineLinked and reached Docker. Removed the redundant RunOnlineLinked selector; old direct linked calls must drop that flag. Rerun runtime proof after the accidentally overlapping test invalidated the first attempt.

Completed: see phuzz-main/code/docs/reports/2026-09-21-online-linked-only.md for verification and limitations.
