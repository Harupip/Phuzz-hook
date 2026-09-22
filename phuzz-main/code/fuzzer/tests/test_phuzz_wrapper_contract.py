import unittest
import shutil
import subprocess
import tempfile
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[2]

class PhuzzWrapperContractTests(unittest.TestCase):

    def test_comparison_prompt_env_and_success_only_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entrypoint = root / "fuzzer" / "online_linked" / "__main__.py"
            entrypoint.parent.mkdir(parents=True)
            entrypoint.touch()
            for name in ("seeds.json", "registry.json"):
                (root / name).write_text("{}")
            probe = root / "probe.ps1"
            probe.write_text(r'''
param($CodeDir, $Root, [int]$DiscoveryExit, [int]$ComparisonExit)
$ErrorActionPreference = "Stop"
. (Join-Path $CodeDir "scripts/wordpress/read-phuzz-env.ps1")
. (Join-Path $CodeDir "scripts/wordpress/invoke-online-linked.ps1")
$settings = Resolve-PhuzzRuntimeSettings -Path (Join-Path $Root "phuzz.env") -BoundParameters @{}
$global:calls = [Collections.Generic.List[object]]::new()
function ComposeStub { $global:LASTEXITCODE = 0 }
function python {
    $global:calls.Add(@($args))
    $global:LASTEXITCODE = if ($args -contains "--prompt-batch") { $ComparisonExit } else { $DiscoveryExit }
}
$failed = $false
try {
    Invoke-OnlineLinked -ScriptRoot $Root -PluginSlug demo -LegacyRunId run-1 `
        -SuggestedSeedsPath (Join-Path $Root "seeds.json") -BootstrapConfig unused `
        -CallbackRegistry (Join-Path $Root "registry.json") -Service fuzzer `
        -OnlineTimeoutSeconds 1 -OnlineMaxVersions 1 -OnlineMaxCandidates 1 `
        -OnlineCampaignTimeoutSeconds 1 -OverridePath unused -ComposeArgs @("ComposeStub", "compose") `
        -OnlineComparePrompt ([bool]$settings["OnlineComparePrompt"])
} catch { $failed = $true }
@{ calls = @($global:calls.ToArray()); failed = $failed; exit_code = $global:LASTEXITCODE } | ConvertTo-Json -Compress -Depth 5
''', encoding="utf-8")
            import json

            for enabled, discovery_exit, comparison_exit in ((0, 0, 0), (1, 0, 0), (1, 0, 1), (1, 0, 2), (1, 7, 0)):
                with self.subTest(enabled=enabled, discovery_exit=discovery_exit, comparison_exit=comparison_exit):
                    (root / "phuzz.env").write_text(f"ONLINE_COMPARE_PROMPT={enabled}\n")
                    result = subprocess.run(
                        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe), str(CODE_DIR), str(root), str(discovery_exit), str(comparison_exit)],
                        capture_output=True, text=True, timeout=20,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    state = json.loads(result.stdout.strip().splitlines()[-1])
                    should_prompt = enabled and discovery_exit == 0
                    self.assertEqual(len(state["calls"]), 2 if should_prompt else 1)
                    self.assertEqual(state["failed"], discovery_exit != 0)
                    self.assertEqual(state["exit_code"], discovery_exit)
                    if should_prompt:
                        self.assertEqual(state["calls"][1][:3], ["-m", "fuzzer.config_comparison.online_linked", "--prompt-batch"])
                        self.assertEqual(Path(state["calls"][1][3]), root / "fuzzer" / "output" / "online-linked" / "run-1")
    def test_runtime_reset_sends_unix_line_endings_from_windows_checkout(self):
        source = (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig")
        function = source.split("function Reset-ZendRuntimeArtifacts", 1)[1].split("function New-PluginOverrideFile", 1)[0]
        # Capture the Docker boundary without deleting campaign artifacts.
        harness = '''
$ErrorActionPreference = "Stop"
function Invoke-Compose {
    param([string[]]$ComposeArgs, [string[]]$AdditionalArgs)
    if (($AdditionalArgs[0..4] -join ' ') -ne 'exec -T web sh -lc') { throw 'Wrong shell invocation' }
    $command = $AdditionalArgs[5]
    if ($command.Contains("`r")) { throw 'CR passed to Unix shell' }
    if (-not $command.StartsWith("set -eu`n")) { throw 'Missing fail-fast shell options' }
    if (($command -split "`n").Count -ne 4) { throw 'Lost reset commands' }
}
'''
        harness += "function Reset-ZendRuntimeArtifacts" + function
        harness += '\nReset-ZendRuntimeArtifacts -ComposeArgs @("docker", "compose")\n'
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "reset-contract.ps1"
            for newline in ("\n", "\r\n"):
                with self.subTest(newline=repr(newline)):
                    script.write_bytes(harness.replace("\n", newline).encode("utf-8"))
                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_guided_wrapper_online_linked_mode_forwards_bounded_discovery(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "online-linked",
                "-PluginSlug", "hookphuzz-rest-get-param-fixture",
                "-UseZendDiscovery",
                "-OnlineTimeoutSeconds", "60",
                "-OnlineMaxVersions", "3",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-wordpress-phuzz.ps1", result.stdout)
        self.assertIn("-UseZendDiscovery", result.stdout)
        self.assertIn("-OnlineTimeoutSeconds 60", result.stdout)
        self.assertIn("-OnlineMaxVersions 3", result.stdout)
        self.assertIn("-OnlineMaxCandidates 32", result.stdout)
        self.assertIn("-OnlineCampaignTimeoutSeconds 3600", result.stdout)

        script = (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("invoke-online-linked.ps1", script)
        self.assertIn('-BootstrapConfig $requiredConfig', script)
        self.assertIn('"HOOKPHUZZ_CMPLOG=1"', (CODE_DIR / "fuzzer" / "online_linked" / "coordinator.py").read_text(encoding="utf-8"))
        launcher = (CODE_DIR / "scripts" / "wordpress" / "invoke-online-linked.ps1").read_text(encoding="utf-8")
        self.assertIn('"--bootstrap-config", $BootstrapConfig', launcher)
        self.assertIn("$env:COMPOSE_FILE", launcher)

    def test_guided_wrapper_reads_changeable_settings_from_env_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            temp_runner_dir = temp_root / "scripts" / "wordpress"
            temp_runner_dir.mkdir(parents=True)
            shutil.copy2(CODE_DIR / "phuzz.ps1", temp_root / "phuzz.ps1")
            shutil.copy2(
                CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1",
                temp_runner_dir / "run-wordpress-phuzz.ps1",
            )
            shutil.copy2(
                CODE_DIR / "scripts" / "wordpress" / "read-phuzz-env.ps1",
                temp_runner_dir / "read-phuzz-env.ps1",
            )
            (temp_root / "phuzz.env").write_text(
                "\n".join(
                    [
                        "ONLINE_TIMEOUT_SECONDS=17",
                        "ONLINE_MAX_VERSIONS=4",
                        "ONLINE_MAX_CANDIDATES=9",
                        "ONLINE_CAMPAIGN_TIMEOUT_SECONDS=123",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "powershell",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(temp_root / "phuzz.ps1"),
                    "-Mode",
                    "online-linked",
                    "-PluginSlug",
                    "demo-plugin",
                    "-DryRun",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-OnlineTimeoutSeconds 17", result.stdout)
        self.assertIn("-OnlineMaxVersions 4", result.stdout)
        self.assertIn("-OnlineMaxCandidates 9", result.stdout)
        self.assertIn("-OnlineCampaignTimeoutSeconds 123", result.stdout)

    def test_guided_wrapper_rejects_invalid_timeout_before_delegating(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "online-linked",
                "-WebTimeoutSeconds",
                "0",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WebTimeoutSeconds", result.stderr)

if __name__ == "__main__":
    unittest.main()
