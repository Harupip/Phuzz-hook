import os
import sys
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from core.utils import get_file_path as canonical_get_file_path
from utils import get_file_path as legacy_get_file_path


class CoreModulePathTests(unittest.TestCase):
    def test_utils_path_remains_relative_to_fuzzer_root(self) -> None:
        expected = f"{os.path.realpath(FUZZER_DIR)}/resources"

        self.assertEqual(canonical_get_file_path("/resources"), expected)
        self.assertEqual(legacy_get_file_path("/resources"), expected)


if __name__ == "__main__":
    unittest.main()
