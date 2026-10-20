import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[2]


class PhuzzPluginBatchTests(unittest.TestCase):
    def prepare(self, root):
        runner_dir = root / "scripts/wordpress"
        runner_dir.mkdir(parents=True)
        shutil.copy2(CODE_DIR / "phuzz.ps1", root / "phuzz.ps1")
        shutil.copy2(CODE_DIR / "scripts/wordpress/read-phuzz-env.ps1", runner_dir / "read-phuzz-env.ps1")
        (root / "phuzz.env").write_text("PLUGIN_ZIP_DIR=selected\nONLINE_CAMPAIGN_TIMEOUT_SECONDS=17\n")
        (root / "failure-mode").write_text("throw")
        selected = root / "selected"
        selected.mkdir()
        for name in ("charlie.zip", "alpha.zip", "bravo.zip"):
            (selected / name).touch()
        (selected / "directory.zip").mkdir()
        (selected / "nested").mkdir()
        (selected / "nested/ignored.zip").touch()
        outside = root / "web/applications/wordpress/_plugins"
        outside.mkdir(parents=True)
        (outside / "outside.zip").touch()
        # A synchronous runner prevents cross-plugin overlap. Failure must not
        # prevent remaining archives from getting their turn.
        (runner_dir / "run-wordpress-phuzz.ps1").write_text(r'''
param($PluginSlug, $WebTimeoutSeconds, $SeedWaitSeconds, $StopOnVulnCount,
    $OnlineTimeoutSeconds, $OnlineMaxVersions, $OnlineMaxCandidates,
    $OnlineCampaignTimeoutSeconds, [switch]$UseZendDiscovery, [switch]$NoComparePrompt)
$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
if (-not $NoComparePrompt) { throw "Batch would block on comparison prompt" }
if ($OnlineCampaignTimeoutSeconds -ne 17) { throw "Lost per-plugin budget" }
$lock = Join-Path $root "active"
if (Test-Path $lock) { throw "Concurrent plugin runners" }
New-Item -ItemType File $lock | Out-Null
try {
    Add-Content (Join-Path $root "calls.txt") "start:$PluginSlug"
    Start-Sleep -Milliseconds 50
    $failureMode = (Get-Content (Join-Path $root "failure-mode")).Trim()
    if ($PluginSlug -eq "bravo" -and $failureMode -eq "throw") { throw "intentional failure" }
    if ($PluginSlug -eq "bravo" -and $failureMode -eq "exit-code") {
        $global:LASTEXITCODE = 7
        return
    }
    Add-Content (Join-Path $root "calls.txt") "end:$PluginSlug"
} finally { Remove-Item -LiteralPath $lock }
''', encoding="utf-8")

    def run_batch(self, root, *args):
        return subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(root / "phuzz.ps1"), "-AllPlugins", *args], capture_output=True, text=True, timeout=20)

    def test_sequential_run_continues_after_error_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root)
            result = self.run_batch(root)
            self.assertEqual((root / "calls.txt").read_text().splitlines(), ["start:alpha", "end:alpha", "start:bravo", "start:charlie", "end:charlie"])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("intentional failure", result.stdout + result.stderr)
            self.assertIn("Batch finished: 2 completed, 1 failed", result.stdout)

    def test_nonzero_runner_status_does_not_poison_next_plugin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root)
            (root / "failure-mode").write_text("exit-code")
            result = self.run_batch(root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Runner returned exit code 7", result.stdout)
            self.assertIn("Run completed: charlie", result.stdout)
            self.assertIn("Batch finished: 2 completed, 1 failed", result.stdout)

    def test_successful_batch_returns_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root)
            (root / "failure-mode").write_text("none")
            result = self.run_batch(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Batch finished: 3 completed, 0 failed", result.stdout)

    def test_dry_run_lists_only_specified_folder_and_starts_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root)
            result = self.run_batch(root, "-DryRun")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "calls.txt").exists())
            self.assertEqual(result.stdout.count("-NoComparePrompt"), 3)
            self.assertLess(result.stdout.index("-PluginSlug alpha"), result.stdout.index("-PluginSlug bravo"))
            for excluded in ("outside", "directory", "ignored"):
                self.assertNotIn(f"-PluginSlug {excluded}", result.stdout)

    def test_empty_folder_and_conflicting_single_plugin_fail_before_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare(root)
            conflict = self.run_batch(root, "-PluginSlug", "alpha")
            self.assertNotEqual(conflict.returncode, 0)
            self.assertFalse((root / "calls.txt").exists())
            for archive in (root / "selected").glob("*.zip"):
                if archive.is_file():
                    archive.unlink()
            empty = self.run_batch(root)
            self.assertNotEqual(empty.returncode, 0)
            self.assertIn("No plugin ZIP", empty.stderr)
            self.assertFalse((root / "calls.txt").exists())


if __name__ == "__main__":
    unittest.main()
