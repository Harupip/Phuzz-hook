import os
import sys
import tempfile
import unittest
from contextlib import chdir
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fuzzer import Fuzzer


class FuzzerOutputTests(unittest.TestCase):
    def test_workers_share_parent_but_reset_only_their_own_output(self):
        with tempfile.TemporaryDirectory() as tmp, chdir(tmp), patch.dict(os.environ, {"HOOKPHUZZ_STOP_ON_VULN": "0"}), patch("fuzzer.os.umask"):
            Path("output/fuzzer-1").mkdir(parents=True)
            legacy = Path("output/fuzzer-1/old.json")
            legacy.write_text("old")
            first = Fuzzer(1, config_only=True)
            self.assertEqual(Path(first.output_dir), Path("output/workers/fuzzer-1"))
            stale = Path(first.output_dir) / "stale.json"
            stale.write_text("stale")
            second = Fuzzer(2, config_only=True)
            sibling = Path(second.output_dir) / "keep.json"
            sibling.write_text("keep")
            Fuzzer(1, config_only=True)
            self.assertFalse(stale.exists())
            self.assertEqual(sibling.read_text(), "keep")
            self.assertEqual(legacy.read_text(), "old")
