# HookPhuzz opcode research

Independent labs for proving opcode-based HTTP parameter discovery one boundary
at a time. Run commands from the repository root.

| Lab | Proves | Authoritative evidence | Boundary |
| --- | --- | --- | --- |
| Phase 0 | PHP opcode shapes and runtime semantics | `phase0/results/raw-opcodes.txt` | No extension |
| Phase 1 | User opcode handler dispatch | `phase1/results/phase1-summary.md` | Invocation count only |
| Phase 2 | Safe operand metadata reads | `phase2/results/phase2-summary.md` | No HTTP provenance |
| Phase 3 | Direct superglobal provenance | `phase3/results/phase3-summary.md` | Normal reads only |
| Phase 4 | Silent direct reads | `phase4/results/phase4-summary.md` | No value transport |
| Phase 5 | Request-local Apache artifacts | `phase5/results/final-verdict.txt` | No WordPress |
| Phase 6 | WordPress compatibility and noise | `phase6/results/final-verdict.txt` | No callback attribution |
| Phase 7 | Static callback attribution | `phase7/results/final-report.md` | Configured callbacks only |
| Phase 8 | UOPZ callback registry handoff | `phase8/results/final-report.md` | No config or replay |
| Phase 9 | Placement, config generation, and replay | `phase9/results/phase9-validation-summary.json` | Fixture-only |
| Phase 10 | Offline fixture integration and merged contracts | `phase10/results/phase10-validation-summary.json` | Live real-plugin gates remain fail-closed |
| Phase 10 CRM | Authenticated real-plugin AJAX discovery | `phase10-crm/results/gate-summary.json` | CRM target only |
| Phase 10 CF7 | Real-plugin REST discovery attempt | `phase10-cf7-rest/results/final-report.md` | Retained run is blocked by authentication |

## Run

```bash
bash research/hookphuzz-opcode/phase0/run.sh
# Replace phase0 with the target lab directory.
```

Each runner owns its pinned environment and `results/`. Later phases do not
consume earlier generated results unless their README explicitly says so.

## Rules for coding agents

- Read this file and the target lab README before changing code.
- Change one lab only. Preserve frozen source copies that make a lab independent.
- Treat docs, filenames, and old results as context, not current runtime proof.
- Claim PASS only from a fresh runner exit and its exact verdict artifact.
- Keep packaging, runtime discovery, replay, fuzzing, and evaluation claims separate.
- Phase 10 offline work must not pull or download. Missing local assets fail closed.
