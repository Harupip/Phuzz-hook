from pathlib import Path
import unittest


FUZZER_DIR = Path(__file__).resolve().parents[1]


class FuzzerStopOnVulnContractTests(unittest.TestCase):
    def test_fuzzer_uses_configured_vulnerability_threshold(self):
        source = (FUZZER_DIR / "fuzzer.py").read_text(encoding="utf-8")
        lines = {line.strip() for line in source.splitlines()}

        self.assertIn(
            'self.stop_on_vuln_count = int(os.environ.get("HOOKPHUZZ_STOP_ON_VULN", "0"))',
            source,
        )
        self.assertIn(
            'self.vulnerability_count = 0',
            source,
        )
        self.assertIn(
            'if self.stop_on_vuln_count > 0 and os.path.exists("/sync-tmpfs/vuln_found"):',
            lines,
        )
        self.assertIn(
            "self.vulnerability_count += 1",
            source,
        )
        self.assertIn(
            "if self.stop_on_vuln_count > 0 and self.vulnerability_count >= self.stop_on_vuln_count:",
            lines,
        )
        self.assertIn('with open("/sync-tmpfs/vuln_found", "w") as f:', lines)
        self.assertIn('f.write(f"Found by {self.fuzzer_id} in {diff}s")', lines)
        self.assertIn("write_finding_artifact(", source)
        self.assertIn("HOOKPHUZZ_FINDING_ARTIFACT", source)
        self.assertNotIn("sys.exit(1337) #TODO: comment me out!", lines)

    def test_threshold_is_loaded_from_phuzz_env_and_forwarded_to_worker(self):
        env_source = (FUZZER_DIR.parent / "phuzz.env").read_text(encoding="utf-8")
        reader_source = (FUZZER_DIR.parent / "scripts" / "wordpress" / "read-phuzz-env.ps1").read_text(encoding="utf-8")
        runner_source = (FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1").read_text(encoding="utf-8")

        self.assertRegex(env_source, r"(?m)^HOOKPHUZZ_STOP_ON_VULN=0$")
        self.assertIn('StopOnVulnCount = Get-PhuzzIntSetting', reader_source)
        self.assertIn('[int]$StopOnVulnCount = 0', runner_source)
        self.assertIn('HOOKPHUZZ_STOP_ON_VULN: $StopOnVulnCount', runner_source)


if __name__ == "__main__":
    unittest.main()
