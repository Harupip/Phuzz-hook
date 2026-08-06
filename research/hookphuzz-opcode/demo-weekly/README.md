# HookPhuzz weekly demo

Run from Bash or WSL:

```bash
bash research/hookphuzz-opcode/demo-weekly/run.sh
```

The command uses only the local generic AJAX demo image and the local PHUZZ
fuzzer image. It creates a uniquely named Compose project and a new directory
under `results/`, then removes only that project's containers and volumes.

For an agent-operated run, follow [AGENT_RUNBOOK.md](AGENT_RUNBOOK.md).

## Before

PHUZZ knows `POST /wp-admin/admin-ajax.php` and the fixed action
`hookphuzz_demo_discover`; its initial config does not contain
`demo_discovered_param`.

## Discovery

The fixture callback executes. Zend opcode instrumentation records its runtime
read of `$_POST['demo_discovered_param']`, attributed to
`hookphuzz_demo_discover_callback`.

## Feedback

The loader converts that runtime evidence to a generated PHUZZ config: the
action remains fixed and `demo_discovered_param` is fuzzable in POST.

## Verification

The real `Fuzzer.load_config` and `Fuzzer.prepare_request` load and prepare
the generated config. Replay sends `HOOKPHUZZ_WEEKLY_DEMO`, reaches the same
callback, and correlates its current request ID across the request, response,
and opcode artifact.

## Benefit

The evaluator does not need to inspect the callback by hand to add every
parameter to the fuzzing configuration. The artifacts separately record source
possibility, runtime observation, generated configuration, and replay proof;
HTTP 200 alone is not accepted.
