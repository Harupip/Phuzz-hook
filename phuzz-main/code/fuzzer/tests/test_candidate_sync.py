import contextlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


FUZZER_DIR = Path(__file__).resolve().parents[1]
import sys

if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from core import candidate as candidate_module
from core.candidate import Candidate


class CandidateSyncTests(unittest.TestCase):
    def test_write_sync_file_publishes_only_complete_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"FUZZER_COMPRESS": "0"}):
            destination = Path(temp_dir) / "candidate.json"
            opened = threading.Event()
            release = threading.Event()
            writer_errors: list[BaseException] = []
            candidate = Candidate(http_target="http://web/", http_method="GET")
            candidate.get_sync_file = lambda: str(destination)

            @contextlib.contextmanager
            def blocking_fuzz_open(path: str, mode: str = "r"):
                with open(path, mode) as handle:
                    opened.set()
                    if not release.wait(timeout=2):
                        raise TimeoutError("test writer was not released")
                    yield handle

            def write_candidate() -> None:
                try:
                    candidate.write_sync_file()
                except BaseException as exc:  # pragma: no cover - surfaced below
                    writer_errors.append(exc)

            with patch.object(candidate_module, "fuzz_open", blocking_fuzz_open):
                writer = threading.Thread(target=write_candidate)
                writer.start()
                self.assertTrue(opened.wait(timeout=2))
                try:
                    self.assertFalse(destination.exists())
                finally:
                    release.set()
                    writer.join(timeout=2)

            self.assertFalse(writer.is_alive())
            self.assertEqual(writer_errors, [])
            with destination.open(encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["http_method"], "GET")


if __name__ == "__main__":
    unittest.main()
