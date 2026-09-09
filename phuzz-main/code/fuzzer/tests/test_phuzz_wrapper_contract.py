import unittest
import subprocess
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[2]


class PhuzzWrapperContractTests(unittest.TestCase):
    def test_guided_wrapper_exposes_menu_and_flag_interfaces(self):
        script_path = CODE_DIR / "phuzz.ps1"

        self.assertTrue(script_path.exists(), "Expected phuzz-main/code/phuzz.ps1 to exist")
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("[ValidateSet(\"default\", \"seed-config\", \"generated\", \"zend\", \"online\", \"online-linked\")]", script)
        self.assertIn("[string]$Mode", script)
        self.assertIn("[switch]$UseZendDiscovery", script)
        self.assertIn("[int]$ZendMaxIterations = 5", script)
        self.assertIn("[int]$OnlineTimeoutSeconds = 120", script)
        self.assertIn("[int]$OnlineMaxVersions = 2", script)
        self.assertIn("[int]$OnlineMaxCandidates = 32", script)
        self.assertIn("[int]$OnlineCampaignTimeoutSeconds = 3600", script)
        self.assertIn("[switch]$DryRun", script)
        self.assertIn("[switch]$Help", script)
        self.assertIn("Read-Host", script)

    def test_guided_wrapper_menu_separates_zend_and_online_modes(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("4) zend", script)
        self.assertIn("5) online", script)
        self.assertIn('switch ($choice)', script)
        self.assertIn('"4" { return "zend" }', script)
        self.assertIn('"5" { return "online" }', script)
        self.assertIn('Read-Host "Select [1-6]"', script)
        self.assertIn('$interactive -and $Mode -in @("online", "online-linked")', script)

    def test_guided_wrapper_removes_recursive_mode_from_public_contract(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn(
            '[ValidateSet("default", "seed-config", "generated", "zend", "online", "online-linked")]',
            script,
        )
        self.assertNotIn("6) recursive", script)
        self.assertNotIn('"6" { return "recursive" }', script)
        self.assertNotIn("[string[]]$RecursiveInputFile", script)

        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "recursive",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)

    def test_guided_wrapper_has_dedicated_zend_mode(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "zend",
                "-PluginSlug", "demo-plugin",
                "-ZendMaxIterations", "7",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-RunGeneratedConfigs", result.stdout)
        self.assertIn("-UseZendDiscovery", result.stdout)
        self.assertIn("-ZendMaxIterations 7", result.stdout)
        self.assertNotIn("-RunOnline", result.stdout)
        self.assertNotIn("-UseEntrypointPipeline", result.stdout)

    def test_guided_wrapper_rejects_zend_flag_on_generated_mode(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "generated",
                "-PluginSlug", "demo-plugin",
                "-UseZendDiscovery",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-Mode zend", result.stderr)

    def test_guided_wrapper_rejects_public_zend_discovery_mode(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "zend-discovery",
                "-PluginSlug",
                "demo-plugin",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("zend-discovery", result.stderr)

    def test_guided_wrapper_generated_mode_does_not_enable_zend_discovery(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "generated",
                "-PluginSlug", "demo-plugin",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-RunGeneratedConfigs", result.stdout)
        self.assertNotIn("-UseZendDiscovery", result.stdout)
        self.assertNotIn("-RunOnline", result.stdout)
        self.assertNotIn("-RunOnlineLinked", result.stdout)
        self.assertNotIn("-Mode zend-discovery", result.stdout)

    def test_guided_wrapper_online_mode_forwards_bounded_discovery(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "online",
                "-PluginSlug", "hookphuzz-entrypoint-direct-fixture",
                "-UseZendDiscovery",
                "-OnlineTimeoutSeconds", "60",
                "-OnlineMaxVersions", "2",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-RunOnline", result.stdout)
        self.assertIn("-UseZendDiscovery", result.stdout)
        self.assertIn("-OnlineTimeoutSeconds 60", result.stdout)
        self.assertIn("-OnlineMaxVersions 2", result.stdout)
        self.assertIn("--bootstrap-config", (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig"))
        self.assertIn("Initialize-ZendCallbackRegistry", (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig"))

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
        self.assertIn("-RunOnlineLinked", result.stdout)
        self.assertIn("-UseZendDiscovery", result.stdout)
        self.assertIn("-OnlineTimeoutSeconds 60", result.stdout)
        self.assertIn("-OnlineMaxVersions 3", result.stdout)
        self.assertIn("-OnlineMaxCandidates 32", result.stdout)
        self.assertIn("-OnlineCampaignTimeoutSeconds 3600", result.stdout)

        script = (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("online_linked_coordinator.py", script)
        self.assertIn("[switch]$RunOnlineLinked", script)
        self.assertIn('"--bootstrap-config", $requiredConfig', script)
        self.assertIn('"HOOKPHUZZ_CMPLOG=1"', (CODE_DIR / "fuzzer" / "hook_energy" / "seed_generation" / "online_linked_coordinator.py").read_text(encoding="utf-8"))
        self.assertIn("$env:COMPOSE_FILE", script)

    def test_guided_wrapper_online_modes_allow_any_local_plugin_zip(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn(
            '$Mode -notin @("generated", "zend", "online", "online-linked")',
            script,
        )

    def test_wordpress_runner_uses_shared_bootstrap_for_online_modes(self):
        script = (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(
            encoding="utf-8-sig"
        )

        self.assertIn(
            'if ($RunGeneratedConfigs -or $RunOnline -or $RunOnlineLinked)',
            script,
        )

    def test_guided_wrapper_rejects_online_entrypoint_pipeline(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "online",
                "-UseZendDiscovery",
                "-UseEntrypointPipeline",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UseEntrypointPipeline", result.stderr)

    def test_guided_wrapper_rejects_zend_discovery_outside_generated_mode(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode", "default",
                "-UseZendDiscovery",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UseZendDiscovery", result.stderr)

    def test_guided_wrapper_delegates_to_existing_wordpress_runner(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("scripts\\wordpress\\run-wordpress-phuzz.ps1", script)
        self.assertIn("RunGeneratedConfigs", script)
        self.assertIn("UseEntrypointPipeline", script)
        self.assertIn("-NoFollowLogs", script)
        self.assertIn("[string]$PluginSlug", script)
        self.assertIn("$runnerParams", script)
        self.assertIn("& $runnerPath @runnerParams", script)

    def test_guided_wrapper_lists_and_passes_local_plugin_slug(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("Get-LocalPluginSlugs", script)
        self.assertIn("web\\applications\\wordpress\\_plugins", script)
        self.assertIn("fuzzer\\configs\\wordpress", script)
        self.assertIn("PluginSlug", script)

    def test_guided_wrapper_dry_run_does_not_prompt_when_mode_is_passed(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "generated",
                "-GeneratedConfigTimeoutSeconds",
                "30",
                "-PluginSlug",
                "gamipress",
                "-NoFollowLogs",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-RunGeneratedConfigs", result.stdout)
        self.assertNotIn("-UseEntrypointPipeline", result.stdout)
        self.assertIn("-GeneratedConfigTimeoutSeconds 30", result.stdout)
        self.assertIn("-PluginSlug gamipress", result.stdout)

    def test_guided_wrapper_generated_mode_can_opt_into_entrypoint_pipeline(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "generated",
                "-PluginSlug",
                "gamipress",
                "-UseEntrypointPipeline",
                "-NoFollowLogs",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-RunGeneratedConfigs", result.stdout)
        self.assertIn("-UseEntrypointPipeline", result.stdout)
        self.assertNotIn("-UseZendDiscovery", result.stdout)

    def test_guided_wrapper_rejects_entrypoint_pipeline_outside_generated_mode(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "default",
                "-UseEntrypointPipeline",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UseEntrypointPipeline", result.stderr)

    def test_guided_wrapper_generated_mode_defaults_to_30_second_config_runs(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "generated",
                "-PluginSlug",
                "gamipress",
                "-NoFollowLogs",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-GeneratedConfigTimeoutSeconds 30", result.stdout)

    def test_guided_wrapper_rejects_generated_config_timeout_above_30(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "generated",
                "-GeneratedConfigTimeoutSeconds",
                "31",
                "-PluginSlug",
                "gamipress",
                "-NoFollowLogs",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GeneratedConfigTimeoutSeconds", result.stderr)

    def test_guided_wrapper_interactive_dry_run_does_not_ask_force_download(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-DryRun",
            ],
            input="3\n\nn\n",
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Force plugin download", result.stdout)
        self.assertIn("-RunGeneratedConfigs", result.stdout)
        self.assertNotIn("-UseZendDiscovery", result.stdout)

    def test_guided_wrapper_interactive_zend_mode_enables_zend_discovery(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-DryRun",
            ],
            input="4\n\nn\n",
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Enable Zend Discovery (two-pass parameter discovery)", script)
        self.assertIn("-RunGeneratedConfigs", result.stdout)
        self.assertIn("-UseZendDiscovery", result.stdout)

    def test_guided_wrapper_generated_mode_lists_plugins_without_manual_config(self):
        plugin_zip = CODE_DIR / "web" / "applications" / "wordpress" / "_plugins" / "zzzz-generated-only.zip"
        config_file = CODE_DIR / "fuzzer" / "configs" / "wordpress" / "zzzz-generated-only.json"
        self.assertFalse(config_file.exists())
        try:
            plugin_zip.write_bytes(b"")
            result = subprocess.run(
                [
                    "powershell",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(CODE_DIR / "phuzz.ps1"),
                    "-DryRun",
                ],
                input="3\n\nn\n",
                capture_output=True,
                text=True,
                timeout=30,
            )
        finally:
            if plugin_zip.exists():
                plugin_zip.unlink()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("zzzz-generated-only", result.stdout)

    def test_guided_wrapper_rejects_invalid_timeout_before_delegating(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "default",
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

    def test_wordpress_runner_keeps_export_cli_and_adds_opt_in_pipeline_branch(self):
        script = (CODE_DIR / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("[switch]$UseEntrypointPipeline", script)
        self.assertIn("[switch]$RunOnline", script)
        self.assertIn("online_config_runner.py", script)
        self.assertIn("OnlineMaxVersions", script)
        self.assertIn("[int]$OnlineMaxCandidates = 32", script)
        self.assertIn("[int]$OnlineCampaignTimeoutSeconds = 3600", script)
        self.assertIn('"--max-candidates", "$OnlineMaxCandidates"', script)
        self.assertIn('"--campaign-seconds", "$OnlineCampaignTimeoutSeconds"', script)
        self.assertIn('"--sync-registry"', script)
        self.assertIn('batch-state.json', script)
        self.assertIn("cli\\export_seeds.py", script)
        self.assertIn("cli\\entrypoint_pipeline.py", script)
        self.assertIn("--output-config-dir", script)
        self.assertIn("--minimal-artifacts", script)
        self.assertIn("-UseEntrypointPipeline requires -RunGeneratedConfigs", script)
        self.assertIn("Write-EntrypointPluginProofFile", script)
        self.assertIn("PLUGIN_GENERATION_PROOF.md", script)
        self.assertIn("entrypoint-proof\\logs", script)
        self.assertIn("Start-Process", script)
        self.assertIn("generated_config_runner.stdout.log", script)
        self.assertIn("generated_config_runner.stderr.log", script)


if __name__ == "__main__":
    unittest.main()
