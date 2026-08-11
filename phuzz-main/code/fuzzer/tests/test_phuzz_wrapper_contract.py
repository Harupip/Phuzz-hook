import json
import os
import shutil
import sys
import tempfile
import unittest
import subprocess
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[2]


class PhuzzWrapperContractTests(unittest.TestCase):
    def test_guided_wrapper_exposes_menu_and_flag_interfaces(self):
        script_path = CODE_DIR / "phuzz.ps1"

        self.assertTrue(script_path.exists(), "Expected phuzz-main/code/phuzz.ps1 to exist")
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("[ValidateSet(\"default\", \"seed-config\", \"generated\", \"recursive\", \"zend-discovery\")]", script)
        self.assertIn("[string]$Mode", script)
        self.assertIn("[switch]$DryRun", script)
        self.assertIn("[switch]$Help", script)
        self.assertIn("[switch]$RunRecursiveConfigs", script)
        self.assertIn("Read-Host", script)

    def test_guided_wrapper_exposes_isolated_zend_discovery_mode(self):
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

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("zend_discovery", result.stdout)
        self.assertIn("--plugin-zip", result.stdout)
        self.assertIn("demo-plugin.zip", result.stdout)
        self.assertNotIn("Delegating to WordPress PHUZZ runner", result.stdout)

    def test_zend_wrapper_prints_seed_config_and_replay_paths(self):
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

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Zend seed artifacts", result.stdout)
        self.assertIn("Zend PHUZZ configs", result.stdout)
        self.assertIn("Zend PHUZZ replay", result.stdout)

    def test_zend_mode_bootstraps_its_own_target_scoped_web_service(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("New-ZendPluginOverrideFile", script)
        self.assertIn("TARGET_APP_PATH: /var/www/html/wp-content/plugins/$SelectedPluginSlug/", script)
        self.assertIn("docker", script)
        self.assertIn("X-Zend-Discovery-Run-ID", script)
        self.assertIn("--write-probe-plan", script)
        self.assertIn("/shared-tmpfs/hook-coverage/requests", script)
        self.assertIn("phuzz-loader-summary.json", script)

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

    def test_guided_wrapper_cleans_recursive_container_artifacts_after_run(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("Clear-RecursiveContainerArtifacts", script)
        self.assertIn("Cleaning recursive hook coverage artifacts", script)
        self.assertIn("docker compose stop --timeout 30 fuzzer-wordpress-plugin", script)
        self.assertIn("/shared-tmpfs/hook-coverage/requests", script)

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

    def test_guided_wrapper_recursive_dry_run_prints_config_runner_when_enabled(self):
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
                "-RunRecursiveConfigs",
                "-DryRun",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("generated_config_runner.py", result.stdout)
        self.assertIn("recursive_config_run_summary.json", result.stdout)
        self.assertIn("--output-format recursive", result.stdout)

    def test_guided_wrapper_recursive_config_runner_is_not_blocked_by_seed_validation_failure(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("$recursiveExitCode -ne $null -and $recursiveExitCode -ne 0 -and -not $RunRecursiveConfigs", script)
        self.assertIn("Recursive seed validation failed; continuing to recursive config runner", script)

    def test_recursive_config_runner_skips_pre_runner_artifact_cleanup(self):
        script = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("if ($copiedContainerArtifacts -and -not $RunRecursiveConfigs)", script)
        self.assertIn("Mode recursive step 4/4: running recursive generated configs", script)

    def test_recursive_config_runner_summary_controls_exit_after_seed_validation_failure(self):
        output_dir = CODE_DIR / "fuzzer" / "output" / "recursive-child-hooks"
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            backup_dir = tmp_path / "recursive-child-hooks.backup"
            if output_dir.exists():
                shutil.move(str(output_dir), str(backup_dir))
            try:
                coverage_dir = tmp_path / "coverage"
                requests_dir = coverage_dir / "requests"
                requests_dir.mkdir(parents=True)
                input_file = requests_dir / "sample.json"
                input_file.write_text(json.dumps({"hook_coverage": {"registered_callbacks": {}}}), encoding="utf-8")

                fake_bin = tmp_path / "bin"
                fake_bin.mkdir()
                calls_log = tmp_path / "calls.log"
                fake_python = tmp_path / "fake_python.py"
                fake_python.write_text(
                    """
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
script = Path(args[0]).name if args else ""
Path(os.environ["CALLS_LOG"]).open("a", encoding="utf-8").write(script + "\\n")

def arg_value(name):
    return args[args.index(name) + 1]

if script == "recursive_child_hook_seeds.py":
    out = Path(arg_value("--output-dir"))
    (out / "configs").mkdir(parents=True, exist_ok=True)
    (out / "recursive_child_hook_seeds.json").write_text(json.dumps({"summary": {"generated": 2, "manual_analysis": 0, "duplicates_skipped": 0, "depth_skipped": 0}}), encoding="utf-8")
    (out / "validation_result.json").write_text(json.dumps({"summary": {"total": 2, "callback_reached": 0}, "validations": [{"status": "no_artifact"}, {"status": "no_artifact"}]}), encoding="utf-8")
    (out / "generated_config_summary.json").write_text(json.dumps({"generated": [{"config_slug": "generated-hooks/one", "hook_name": "hook-one", "callback_id": "cb-one"}, {"config_slug": "generated-hooks/two", "hook_name": "hook-two", "callback_id": "cb-two"}]}), encoding="utf-8")
    (out / "configs" / "one.json").write_text("{}", encoding="utf-8")
    (out / "configs" / "two.json").write_text("{}", encoding="utf-8")
    sys.exit(1)

if script == "generated_config_runner.py":
    output = Path(arg_value("--output-file"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"total_configs": 2, "passed": 2, "failed": 0, "timed_out": 0, "results": [{"status": "callback_reached"}, {"status": "callback_reached"}]}), encoding="utf-8")
    sys.exit(1)

sys.exit(2)
""",
                    encoding="utf-8",
                )
                (fake_bin / "python.cmd").write_text(f'@"{sys.executable}" "{fake_python}" %*\n', encoding="utf-8")
                (fake_bin / "docker.cmd").write_text("@exit /b 0\n", encoding="utf-8")
                env = os.environ.copy()
                env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
                env["CALLS_LOG"] = str(calls_log)

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
                        str(input_file),
                        "-RecursiveHookCoverageDir",
                        str(coverage_dir),
                        "-RunRecursiveConfigs",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls_log.read_text(encoding="utf-8").splitlines(), ["recursive_child_hook_seeds.py", "generated_config_runner.py"])
                summary = json.loads((output_dir / "recursive_config_run_summary.json").read_text(encoding="utf-8-sig"))
                self.assertEqual(summary["seed_validation_status"], "failed")
                self.assertEqual(summary["seed_validation_failed_count"], 2)
                self.assertEqual(summary["config_runner_status"], "passed")
                self.assertIn(summary["overall_e2e_status"], {"passed_with_seed_validation_warning", "passed_config_runner"})
            finally:
                if output_dir.exists():
                    shutil.rmtree(output_dir)
                if backup_dir.exists():
                    shutil.move(str(backup_dir), str(output_dir))

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
        self.assertIn("export_cli.py", script)
        self.assertIn("pipeline_cli.py", script)
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
