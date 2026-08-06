# Weekly demo agent runbook

## Scope

Run and report the weekly HookPhuzz demo in the local checkout only. Do not
edit source, run Phase 10–13, delete Docker images/volumes, or use `docker
system prune`.

## Preconditions

From the repository root, check Docker and the required local images:

```powershell
docker version
docker image inspect hookphuzz-opcode-demo-generic-ajax-wordpress:latest
docker image inspect code-fuzzer-wordpress-plugin:latest
```

If Docker has no Server response, report `DEMO_WEEKLY_BLOCKED_DOCKER`.
If either image is missing, report `DEMO_WEEKLY_BLOCKED_MISSING_LOCAL_IMAGES`.
Do not pull or build images: this demo is intentionally run from local images.

## Run

Run exactly this command from the repository root:

```powershell
bash research/hookphuzz-opcode/demo-weekly/run.sh
```

Do not start or select containers in Docker Desktop manually. The script
creates a unique `hpweekly-*` Compose project and cleans up only that project.

## Validate

Find the newest run directory and inspect its gate report:

```powershell
$run = Get-ChildItem research\hookphuzz-opcode\demo-weekly\results -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

Get-Content (Join-Path $run.FullName 'final-gate-status.json')
```

Report `DEMO_WEEKLY_PASS` only when all are true:

- process exit code is `0`;
- stdout contains `DEMO_WEEKLY_PASS`;
- `final-gate-status.json` has `status: PASS`, `failed_gates: []`, and 17
  passed gates;
- the same run directory contains `generated-config.json`,
  `discovery-artifact.json`, `replay-artifact.json`, `callback-proof.json`,
  and `demo-summary.md`.

## Failure report

On any other outcome, report `DEMO_WEEKLY_PARTIAL` and provide:

- the run directory;
- `final-gate-status.json` when present;
- the last 80 lines of `run.stdout.log` and `run.stderr.log`;
- the exact failed gate names.

Do not reuse an earlier run as proof and do not attempt broad Docker cleanup.
