"""Executable package and dependency boundaries for online-linked extraction."""

import ast
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))


class OnlineLinkedPackageTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is required')
    def test_launcher_restores_environment_and_cwd_after_python_success_or_failure(self):
        launcher = FUZZER_DIR.parent / 'scripts/wordpress/invoke-online-linked.ps1'
        self.assertTrue(launcher.is_file(), 'linked launch needs a dedicated owner')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'fuzzer/online_linked').mkdir(parents=True)
            (root / 'fuzzer/online_linked/__main__.py').touch()
            (root / 'seeds.json').write_text('{}')
            (root / 'registry.json').write_text('{}')
            quote = lambda path: "'" + str(path).replace("'", "''") + "'"
            for exit_code in (0, 9):
                with self.subTest(exit_code=exit_code):
                    script = root / 'check.ps1'
                    script.write_text(f'''
$ErrorActionPreference = 'Stop'
. {quote(launcher)}
$env:COMPOSE_FILE = 'existing-compose.yml'
$env:PYTHONPATH = 'existing-python-path'
$before = (Get-Location).Path
$global:captured = @{{}}
function docker {{
    $global:captured.stop = @($args)
    $global:LASTEXITCODE = 0
}}
function python {{
    $global:captured.python = @($args)
    $global:captured.compose = $env:COMPOSE_FILE
    $global:captured.pythonpath = $env:PYTHONPATH
    $global:captured.cwd = (Get-Location).Path
    $global:LASTEXITCODE = {exit_code}
}}
try {{
    Invoke-OnlineLinked -ScriptRoot {quote(root)} -PluginSlug fixture -LegacyRunId run-test `
        -SuggestedSeedsPath {quote(root / 'seeds.json')} -BootstrapConfig {quote(root / 'bootstrap.json')} `
        -CallbackRegistry {quote(root / 'registry.json')} -Service fuzzer-test `
        -OnlineTimeoutSeconds 17 -OnlineMaxVersions 3 -OnlineMaxCandidates 7 `
        -OnlineCampaignTimeoutSeconds 123 -OverridePath {quote(root / 'override.yml')} `
        -ComposeArgs @('docker', 'compose', '-f', 'docker-compose.yml')
}} catch {{ $global:captured.error = $_.Exception.Message }}
$global:captured.restoredCompose = $env:COMPOSE_FILE
$global:captured.restoredPython = $env:PYTHONPATH
$global:captured.restoredCwd = ((Get-Location).Path -eq $before)
Write-Output ('RESULT=' + ($global:captured | ConvertTo-Json -Compress -Depth 5))
''', encoding='utf-8')
                    result = subprocess.run(
                        ['pwsh', '-NoProfile', '-NonInteractive', '-File', str(script)],
                        cwd=root, capture_output=True, text=True, timeout=20,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    payload = json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith('RESULT=')))
                    self.assertEqual(payload['python'][:2], ['-m', 'online_linked'])
                    self.assertEqual(list(map(str, payload['stop'][-4:])), ['stop', '--timeout', '30', 'fuzzer-test'])
                    self.assertEqual(payload['cwd'], str(root))
                    self.assertIn(str(root / 'fuzzer'), payload['pythonpath'])
                    self.assertEqual(payload['compose'], 'docker-compose.yml;' + str(root / 'override.yml'))
                    for flag, value in [('--max-seconds', '17'), ('--max-versions', '3'),
                                        ('--max-candidates', '7'), ('--campaign-seconds', '123')]:
                        self.assertEqual(payload['python'][payload['python'].index(flag) + 1], value)
                    self.assertEqual(payload['restoredCompose'], 'existing-compose.yml')
                    self.assertEqual(payload['restoredPython'], 'existing-python-path')
                    self.assertTrue(payload['restoredCwd'])
                    self.assertEqual('error' in payload, exit_code != 0)

    def test_package_entrypoints_run_without_starting_workers(self):
        for module in ('online_linked', 'online_linked.probe_sender'):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, '-B', '-m', module, '--help'],
                    cwd=FUZZER_DIR, capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)

    def test_linked_implementation_has_no_old_coordinator_dependency(self):
        package = FUZZER_DIR / 'online_linked'
        self.assertTrue(package.is_dir(), 'linked implementation needs its own package')
        for path in package.glob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn('online_config_runner', node.module or '', str(path))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn('online_config_runner', alias.name, str(path))

    def test_shared_runtime_does_not_import_linked_mode(self):
        violations = []
        for path in FUZZER_DIR.rglob('*.py'):
            relative = path.relative_to(FUZZER_DIR)
            if relative.parts[0] in {'tests', 'online_linked', 'config_comparison'}:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
                modules = ([node.module or ''] if isinstance(node, ast.ImportFrom)
                           else [a.name for a in node.names] if isinstance(node, ast.Import) else [])
                if any(any(part.startswith('online_linked') or part == 'probe_sender'
                           for part in module.split('.')) for module in modules):
                    violations.append(str(relative))
        self.assertEqual(violations, [])

    def test_shared_selector_preserves_bootstrap_callback_and_fuzz_gate(self):
        name = 'hook_energy.seed_generation.online_common'
        self.assertIsNotNone(importlib.util.find_spec(name), 'shared selection must not instantiate online mode')
        from hook_energy.seed_generation.online_common import select_v0
        from seed_generation.config.config_exporter import SeedConfigSkip

        item = {
            'hook_name': 'wp_ajax_fixture', 'callback_id': 'callback',
            'callback_repr': 'Fixture::callback',
            'seed': {'path': '/wp-admin/admin-ajax.php', 'method': 'POST', 'resolved_method': 'POST'},
        }
        config = {
            'target': 'http://web/wp-admin/admin-ajax.php', 'methods': ['POST'],
            'body_params': {'fuzz': ['value'], 'data': [{'name': 'value', 'value': 'original'}]},
        }

        def skip(*args, **kwargs):
            raise SeedConfigSkip('fixture requires bootstrap')

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested, bootstrap = root / 'suggested.json', root / 'bootstrap.json'
            suggested.write_text(json.dumps({'suggested_seeds': [item]}), encoding='utf-8')
            bootstrap.write_text(json.dumps(config), encoding='utf-8')
            selected = select_v0(suggested, bootstrap, build_config_fn=skip)
            self.assertIsNotNone(selected)
            self.assertEqual(selected[1]['metadata']['callback_id'], 'callback')
            self.assertEqual(selected[1]['body_params'], config['body_params'])
            self.assertEqual(selected[1]['config_type'], 'fuzzing_ready')
            config['body_params']['fuzz'] = []
            bootstrap.write_text(json.dumps(config), encoding='utf-8')
            self.assertIsNone(select_v0(suggested, bootstrap, build_config_fn=skip))


if __name__ == '__main__':
    unittest.main()
