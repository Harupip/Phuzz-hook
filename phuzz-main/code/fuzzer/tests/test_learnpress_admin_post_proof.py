from __future__ import annotations

import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
SCRIPT = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
OVERRIDE = FUZZER_DIR.parent / "web" / "applications" / "wordpress" / "_overrides" / "99-wordpress.php"


class LearnPressAdminPostProofContractTests(unittest.TestCase):
    def test_learnpress_probe_uses_runtime_registered_action_and_fixed_nonce(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8-sig")

        self.assertIn("function Invoke-ZendLearnPressAdminPostProof", script)
        self.assertIn("registered_callbacks", script)
        self.assertIn("admin_post_lp_async_lp_background_single_course", script)
        self.assertIn("admin_post_lp_async_lp_background_single_email", script)
        self.assertIn("admin_post_lp_async_lp_background_single_thim_cache", script)
        self.assertIn("_nonce = $nonce", script)
        self.assertIn('action = $action', script)
        self.assertIn('"hookphuzz-invalid-nonce-sentinel"', script)
        self.assertIn("nonce-proof.json", script)

    def test_learnpress_nonce_proof_requires_original_core_and_records_context(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8-sig")
        override = OVERRIDE.read_text(encoding="utf-8-sig")

        self.assertIn("HOOKPHUZZ_STRICT_NONCE_PROOF", script)
        self.assertIn("wp_create_nonce", script)
        self.assertIn("wp_verify_nonce", script)
        self.assertIn("nonce_action", script)
        self.assertIn("authenticated_user_id", script)
        self.assertIn("verification_result", script)
        self.assertIn("HOOKPHUZZ_STRICT_NONCE_PROOF", override)
        self.assertIn("if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) !== '1' )", override)

    def test_learnpress_final_replay_keeps_action_and_nonce_out_of_fuzzable_params(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8-sig")

        self.assertIn("fixed_params", script)
        self.assertIn('"action", "_nonce"', script)
        self.assertIn("fuzzable_params", script)
        self.assertIn("callback_reached", script)
        self.assertIn("parameter_path_matched", script)
        self.assertIn("final_replay", script)


if __name__ == "__main__":
    unittest.main()
