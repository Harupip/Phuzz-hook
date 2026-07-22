# HookPhuzz Generic AJAX Demo

## Run on another machine

Prerequisites: Git, Docker Desktop (running), and Bash. PHP is compiled in the
Docker image, so it is not required on the host for the demo.

```bash
git clone https://github.com/Harupip/Phuzz-hook.git
cd Phuzz-hook
git switch feature/hookphuzz-opcode-phases
cd research/hookphuzz-opcode/phase-demo-generic-ajax
HOOKPHUZZ_DEMO_HOOK=wp_ajax_nopriv_hookphuzz_demo_nested bash ./run.sh
```

From Windows PowerShell:

```powershell
cd C:\path\to\Phuzz-hook\research\hookphuzz-opcode\phase-demo-generic-ajax
$env:HOOKPHUZZ_DEMO_HOOK = 'wp_ajax_nopriv_hookphuzz_demo_nested'
bash ./run.sh
Remove-Item Env:HOOKPHUZZ_DEMO_HOOK
```

Edit only `wordpress/wp-content/plugins/hookphuzz-demo-target/hookphuzz-demo-target.php`, then run:

```bash
cd research/hookphuzz-opcode/phase-demo-generic-ajax
./run.sh
```

The runtime UOPZ registry, not PHP source parsing, selects one `wp_ajax_*` or
`wp_ajax_nopriv_*` registration. Set `HOOKPHUZZ_DEMO_HOOK` when the target
plugin registers more than one AJAX hook:

```bash
HOOKPHUZZ_DEMO_HOOK=wp_ajax_nopriv_save_profile ./run.sh
```

The nested `if` / `else` fixture can be run explicitly:

```bash
HOOKPHUZZ_DEMO_HOOK=wp_ajax_nopriv_hookphuzz_demo_nested ./run.sh
```

The focused no-Docker checks are:

```bash
php tests/recursive-discovery.php
php verifier/run.php --self-check
```

`./run.sh all` is identical to the default command. `./run.sh clean` removes
only this demo's Docker resources and generated `results/` directory.

On PASS, `results/` keeps `executed-replay-configs.json` (every request config
actually sent, in order), `recursive-discovery.json` (Phase A gates and fuzz
parameters), `phuzz-config.json` (the direct PHUZZ config), `config-flow.md`,
and `run.stdout.log`. The default callback demonstrates `test=1` unlocking
the fuzzable GET parameter `mo`.
The isolated image compiles the proven Phase 9 extension source at build time;
it does not edit Phase 9.
