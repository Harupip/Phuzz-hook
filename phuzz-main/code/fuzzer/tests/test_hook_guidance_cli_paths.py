import sys
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.cli import build_argument_parser as legacy_parser
from hook_guidance.coverage.cli import build_argument_parser as canonical_parser


class HookGuidanceCliPathTests(unittest.TestCase):
    def test_default_output_paths_remain_under_phuzz_main(self) -> None:
        output_dir = FUZZER_DIR.parents[1] / "output"

        for parser_factory in (canonical_parser, legacy_parser):
            args = parser_factory().parse_args([])
            self.assertEqual(Path(args.requests_dir), output_dir / "requests")
            self.assertEqual(Path(args.state_file), output_dir / "hook_energy_state.json")
            self.assertEqual(Path(args.summary_file), output_dir / "hook_energy_summary.json")


if __name__ == "__main__":
    unittest.main()
