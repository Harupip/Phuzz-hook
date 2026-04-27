from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

if "bleach" not in sys.modules:
    bleach_stub = types.ModuleType("bleach")
    bleach_stub.clean = lambda value, strip=True: value
    sys.modules["bleach"] = bleach_stub

if "esprima" not in sys.modules:
    esprima_stub = types.ModuleType("esprima")
    esprima_stub.parseScript = lambda value: None
    sys.modules["esprima"] = esprima_stub

if "bs4" not in sys.modules:
    bs4_stub = types.ModuleType("bs4")
    bs4_stub.BeautifulSoup = lambda *args, **kwargs: None
    bs4_stub.element = types.SimpleNamespace(Tag=object)
    sys.modules["bs4"] = bs4_stub

from vulncheck import WebPathBasedPathTraversalVulnCheck


class WebPathBasedPathTraversalVulnCheckTests(unittest.TestCase):
    def test_init_does_not_fail_when_web_paths_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_file = Path(tmpdir) / "web-paths.txt"
            with patch.object(WebPathBasedPathTraversalVulnCheck, "WEB_PATHS_FILE", missing_file):
                checker = WebPathBasedPathTraversalVulnCheck("/tmp/path-errors")

            self.assertEqual(checker.web_paths, [])

    def test_checker_can_reload_web_paths_after_file_appears(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            web_paths_file = Path(tmpdir) / "web-paths.txt"
            with patch.object(WebPathBasedPathTraversalVulnCheck, "WEB_PATHS_FILE", web_paths_file):
                checker = WebPathBasedPathTraversalVulnCheck("/tmp/path-errors")
                self.assertEqual(checker.web_paths, [])

                web_paths_file.write_text("/var/www/html/index.php\n", encoding="utf-8")

                checker.refresh_web_paths()

            self.assertEqual(checker.web_paths, ["/var/www/html/index.php"])


if __name__ == "__main__":
    unittest.main()
