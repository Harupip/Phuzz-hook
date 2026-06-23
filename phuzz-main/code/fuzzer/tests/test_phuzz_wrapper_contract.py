import unittest
import subprocess
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[2]


class PhuzzWrapperContractTests(unittest.TestCase):
    def test_guided_wrapper_exposes_menu_and_flag_interfaces(self):
        script_path = CODE_DIR / "phuzz.ps1"

        self.assertTrue(script_path.exists(), "Expected phuzz-main/code/phuzz.ps1 to exist")
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("[ValidateSet(\"default\", \"seed-config\", \"generated\", \"recursive\")]", script)
        self.assertIn("[string]$Mode", script)
        self.assertIn("[switch]$DryRun", script)
        self.assertIn("[switch]$Help", script)
        self.assertIn("Read-Host", script)

    def test_guided_wrapper_delegates_to_existing_wordpress_runner(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("scripts\\wordpress\\run-wordpress-phuzz.ps1", script)
        self.assertIn("RunGeneratedConfigs", script)
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

    def test_guided_wrapper_exposes_recursive_child_hook_mode(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("recursive_child_hook_seeds.py", script)
        self.assertIn("Copy-ContainerRequestArtifacts", script)
        self.assertIn("Write-RecursiveContainerTarget", script)
        self.assertIn("Mode recursive target plugin", script)
        self.assertIn("Write-RecursiveSummary", script)
        self.assertIn("No child-hook metadata found", script)
        self.assertIn("Start-ArtifactSyncJob", script)
        self.assertIn("--base-url", script)
        self.assertIn("--hook-coverage-dir", script)
        self.assertIn("--max-hook-depth", script)

    def test_guided_wrapper_recursive_dry_run_prints_helper_command(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "recursive",
                "-RecursiveInputFile",
                "sample.json",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("recursive_child_hook_seeds.py", result.stdout)
        self.assertIn("--input-file sample.json", result.stdout)
        self.assertIn("--base-url http://localhost:8080", result.stdout)
        self.assertIn("--hook-coverage-dir", result.stdout)
        self.assertNotIn("--skip-validation", result.stdout)

    def test_guided_wrapper_recursive_dry_run_without_input_prints_container_placeholder(self):
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

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("web:/shared-tmpfs/hook-coverage/requests", result.stdout)
        self.assertNotIn("--input-file \n", result.stdout)
        self.assertIn("Mode recursive step", result.stdout)

    def test_guided_wrapper_recursive_dry_run_prepares_selected_plugin_first(self):
        result = subprocess.run(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(CODE_DIR / "phuzz.ps1"),
                "-Mode",
                "recursive",
                "-PluginSlug",
                "gamipress",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Mode recursive step 0/4", result.stdout)
        self.assertIn("-PluginSlug gamipress", result.stdout)
        self.assertIn("-NoFollowLogs", result.stdout)
        self.assertIn("recursive_child_hook_seeds.py", result.stdout)

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
                "300",
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
        self.assertIn("-GeneratedConfigTimeoutSeconds 300", result.stdout)
        self.assertIn("-PluginSlug gamipress", result.stdout)

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


if __name__ == "__main__":
    unittest.main()
