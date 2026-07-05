from pathlib import Path
import unittest


FUZZER_DIR = Path(__file__).resolve().parents[1]


class FuzzerStopOnVulnContractTests(unittest.TestCase):
    def test_fuzzer_signals_and_exits_after_first_vulnerability(self):
        source = (FUZZER_DIR / "fuzzer.py").read_text(encoding="utf-8")
        lines = {line.strip() for line in source.splitlines()}

        self.assertIn('with open("/sync-tmpfs/vuln_found", "w") as f:', lines)
        self.assertIn('f.write(f"Found by {self.fuzzer_id} in {diff}s")', lines)
        self.assertIn("sys.exit(1337) #TODO: comment me out!", lines)


if __name__ == "__main__":
    unittest.main()
