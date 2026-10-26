# Compact request artifacts implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce repeated hook metadata without reducing discovery evidence, and leave a reproducible change record.

**Architecture:** v4 requests retain blindspot IDs instead of duplicate descriptors. Existing Python readers resolve those IDs against the full registered map in the same request; v3 remains readable. Keep all runtime identities, child metadata and Zend events.

**Tech Stack:** PHP instrumentation, Python unittest, existing Docker PHP CLI for producer checks.

**Spec:** `docs/superpowers/specs/2026-10-26-compact-request-artifacts-design.md`

## Global constraints

- Preserve pre-existing working-tree changes; work in the current feature checkout used by the running Docker mounts.
- No destructive cleanup, schema rewrite of historical files, automatic commit or unrelated config/checklist changes.
- Do not truncate request input or Zend evidence. Diagnostics identify paths and reasons, not input contents.

## Review focus

- v3 and v4 must produce identical validation observations and recovered callback metadata.
- Inactive callbacks must not become blindspots; explicit IDs define the set.
- Child registration/REST metadata must survive reconstruction unchanged.
- Malformed references and JSON must identify the failed artifact.
- Encoding/write/rename failure must preserve an existing complete destination.

## Task 1: Producer, compatible readers and diagnostics

Files: PHP `web/instrumentation/hook_coverage/uopz_hook_wp.php`; Python `seed_generation/verification/seed_validator.py`, `hook_energy/bootstrap_entry_discovery.py`, `hook_energy/seed_generation/generated_config_runner.py`; new `tests/test_request_artifact_compaction.py` (all under `phuzz-main/code/` or `phuzz-main/code/fuzzer/`).

- [x] Add tests comparing v3/v4 validation and fallback registry, invalid references, actual PHP producer output and failed writes, and named JSON errors.
- [x] Run tests and record expected failures before editing production code.
- [x] Remove duplicate per-request blindspot map, mark v4, compact and validate writes; resolve IDs in the two blindspot readers; annotate replay decode failures.
- [x] Run focused tests, existing reader/discovery tests and the available full suite; separate environment failures from regressions.
- [x] Measure old/new bytes and semantic equivalence using a preserved real request. Record findings, limits and rollback in a report linked from the architecture docs.

## Execution ledger

- 2026-10-26: Audited all production `blindspot_callbacks` consumers. Only seed validation and the per-request fallback registry require reconstruction; aggregate readers retain the old full map. No new worktree is required for this scoped change in the existing mounted feature checkout. No automatic commit is authorized.
- 2026-10-27: Completed 11 focused checks and live HTTP smoke. Real preserved request shrank 64.73%; expanding blindspot references reproduces its old JSON object. Independent review found an alias-normalization edge; red/green regression added and existing normalization restored. Final full suite: 703 tests, 16 failures, 1 error, 4 skipped; the same failing methods reproduce 16 failures/1 error with HEAD Python modules. No unrelated fixes. Permanent report: `phuzz-main/code/docs/reports/2026-10-26-request-artifact-compaction.md`.
