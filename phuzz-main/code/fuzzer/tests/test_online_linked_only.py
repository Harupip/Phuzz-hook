import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 required")
class OnlineLinkedOnlyTests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(CODE_DIR / "phuzz.ps1"), *args],
            capture_output=True, text=True, timeout=20,
        )

    def test_removed_modes_fail_before_delegation(self):
        for mode in ("default", "seed-config", "generated", "zend", "online"):
            with self.subTest(mode=mode):
                result = self.invoke("-Mode", mode, "-PluginSlug", "fixture", "-DryRun")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Delegating", result.stdout)

    def test_default_mode_runs_linked_without_prompting(self):
        result = self.invoke("-PluginSlug", "fixture", "-DryRun")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-wordpress-phuzz.ps1", result.stdout)
        self.assertIn("-UseZendDiscovery", result.stdout)

    def test_explicit_linked_enables_zend_without_extra_flag(self):
        result = self.invoke("-Mode", "online-linked", "-PluginSlug", "fixture", "-DryRun")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-UseZendDiscovery", result.stdout)

    def test_dry_run_without_arguments_does_not_prompt(self):
        result = self.invoke("-DryRun")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-wordpress-phuzz.ps1", result.stdout)

    def test_direct_runner_rejects_legacy_switches_before_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A regression must never start real containers during this test.
            stub = Path(tmp) / ("docker.cmd" if os.name == "nt" else "docker")
            stub.write_text("@exit /b 99\n" if os.name == "nt" else "#!/bin/sh\nexit 99\n")
            stub.chmod(0o755)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"])
            for option in ("RunOnline", "RunGeneratedConfigs", "UseEntrypointPipeline"):
                with self.subTest(option=option):
                    result = subprocess.run(
                        ["pwsh", "-NoProfile", "-NonInteractive", "-File",
                         str(CODE_DIR / "run-wordpress-phuzz.ps1"), "-" + option],
                        capture_output=True, text=True, timeout=20, env=env,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("Checking Docker", result.stdout)

    def test_obsolete_options_are_rejected(self):
        for option, value in (("GeneratedConfigTimeoutSeconds", "5"), ("ZendMaxIterations", "3"),
                              ("UseEntrypointPipeline", None), ("KeepDebugArtifacts", None)):
            with self.subTest(option=option):
                args = ["-Mode", "online-linked", "-PluginSlug", "fixture", "-DryRun", "-" + option]
                if value:
                    args.append(value)
                result = self.invoke(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Delegating", result.stdout)
