from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = "research/hookphuzz-opcode/phase13/run.sh"


def bash_path(path: Path) -> str:
    value = str(path).replace("\\", "/")
    if len(value) >= 2 and value[1] == ":":
        return f"/mnt/{value[0].lower()}{value[2:]}"
    return value


def bash(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-lc", textwrap.dedent(code)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class RunShMenuTests(unittest.TestCase):
    def test_menu_discovery_uses_zip_files_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "gamipress.zip").touch()
            (root / "contact-form-7.zip").touch()
            (root / "not-a-plugin.zip").mkdir()
            result = bash(f"""
                source {SCRIPT}
                plugin_zip_dir="{bash_path(root)}"
                discover_plugin_slugs
            """)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["contact-form-7", "gamipress"])

    def test_invalid_menu_choice_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "gamipress.zip").touch()
            result = bash(f"""
                source {SCRIPT}
                plugin_zip_dir="{bash_path(root)}"
                read_plugin_menu <<< 2
            """)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid plugin selection", result.stderr)

    def test_select_plugin_is_mutually_exclusive(self):
        result = bash(f"""
            source {SCRIPT}
            parse_args --select-plugin --plugin gamipress
            normalize_selection
        """)
        self.assertEqual(result.returncode, 2)
        self.assertIn("mutually exclusive", result.stderr)

    def test_selected_menu_item_maps_to_phase13_env(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "contact-form-7.zip").touch()
            (root / "gamipress.zip").touch()
            result = bash(f"""
                source {SCRIPT}
                plugin_zip_dir="{bash_path(root)}"
                select_plugin=1
                normalize_selection <<< 2
                phase13_env_args run-test
            """)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "PHASE13_RUN_ID=run-test",
                "PHASE13_RUN_MODE=exploratory",
                "PHASE13_SELECTED_PLUGINS=gamipress",
            ],
        )

    def test_no_arg_env_remains_canonical(self):
        result = bash(f"""
            source {SCRIPT}
            parse_args
            normalize_selection
            phase13_env_args run-test
        """)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["PHASE13_RUN_ID=run-test"])


if __name__ == "__main__":
    unittest.main()
