# HookPhuzz opcode research

Each phase is isolated. On another machine, check out this branch, install
Docker Desktop and Bash, then run the phase you need from the repository root:

```bash
bash research/hookphuzz-opcode/phase0/run.sh
# ...
bash research/hookphuzz-opcode/phase10/run.sh
```

Every runner builds its own pinned Docker environment, creates `results/`,
and exits non-zero when a required gate fails. `results/` is intentionally not
versioned: it is fresh, machine-local evidence. Read the target phase's
`README.md` before running it; later phases do not require an earlier phase's
generated results.
