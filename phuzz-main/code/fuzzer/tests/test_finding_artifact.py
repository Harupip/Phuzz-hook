import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from core.finding_artifact import build_finding_record, write_finding_artifact


class FindingArtifactTests(unittest.TestCase):
    def test_finding_record_keeps_vulnerability_and_mutation_provenance(self):
        candidate = SimpleNamespace(
            coverage_id="coverage-123",
            fuzzer_id=7,
            http_target="http://web/wp-admin/admin-ajax.php",
            http_method="POST",
            fixed_params={"body_params": {"action": "demo"}},
            fuzz_params={"query_params": {"album_id": "PAYLOAD"}},
            mutated_param_type="query_params",
            mutated_param_name="album_id",
            mutation_source="normal",
            hook_request_id="request-123",
        )

        record = build_finding_record(candidate, vuln_type="SQLi", run_id="run-123")

        self.assertEqual(record["vuln_type"], "SQLi")
        self.assertEqual(record["mutated_param_type"], "query_params")
        self.assertEqual(record["mutated_param_name"], "album_id")
        self.assertEqual(record["payload"], "PAYLOAD")
        self.assertEqual(record["coverage_id"], "coverage-123")

    def test_finding_artifact_is_written_as_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "finding.json"
            write_finding_artifact(
                path,
                run_id="run-123",
                fuzzer_id=7,
                findings=[{"vuln_type": "XSS", "coverage_id": "coverage-123"}],
            )

            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["run_id"], "run-123")
        self.assertEqual(payload["fuzzer_id"], 7)
        self.assertEqual(payload["findings"][0]["vuln_type"], "XSS")


if __name__ == "__main__":
    unittest.main()
