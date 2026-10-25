import json
import os
import subprocess
import unittest
import uuid


@unittest.skipUnless(os.environ.get("HOOKPHUZZ_OPCODE_TEST_CONTAINER"), "requires a Zend test container")
class OpcodeIdLimitsTests(unittest.TestCase):
    def artifact(self, request_id, run_id):
        container = os.environ["HOOKPHUZZ_OPCODE_TEST_CONTAINER"]
        extension = os.environ.get("HOOKPHUZZ_OPCODE_TEST_EXTENSION", "hookphuzz_opcode")
        path = f"/shared/opcode-events/{request_id}.json"
        try:
            subprocess.run(
                ["docker", "exec", "-e", f"HTTP_X_FUZZER_COVID={request_id}",
                 "-e", f"HTTP_X_HOOKPHUZZ_RUN_ID={run_id}", container,
                 "php", "-n", "-d", f"extension={extension}", "-r", ""],
                check=True, capture_output=True, timeout=15,
            )
            result = subprocess.run(
                ["docker", "exec", container, "cat", path],
                capture_output=True, timeout=15,
            )
            return json.loads(result.stdout) if result.returncode == 0 else None
        finally:
            subprocess.run(["docker", "exec", container, "rm", "-f", "--", path],
                           check=True, capture_output=True, timeout=15)

    def test_run_id_accepts_256_bytes_and_preserves_character_validation(self):
        for run_id, accepted in [("a" * n, n <= 256) for n in (128, 129, 256, 257)] + [
            ("", False), ("bad/id", False), ("-bad", False),
        ]:
            with self.subTest(length=len(run_id), prefix=run_id[:8]):
                artifact = self.artifact("id-limit-" + uuid.uuid4().hex, run_id)
                self.assertIsNotNone(artifact)
                self.assertEqual(artifact.get("run_id"), run_id if accepted else None)

    def test_request_id_still_rejects_more_than_128_bytes(self):
        for length in (128, 129):
            with self.subTest(length=length):
                request_id = ("id-limit-" + uuid.uuid4().hex).ljust(length, "a")
                artifact = self.artifact(request_id, "id-limit-run")
                if length <= 128:
                    self.assertIsNotNone(artifact)
                    self.assertEqual(artifact["request_id"], request_id)
                else:
                    self.assertIsNone(artifact)


if __name__ == "__main__":
    unittest.main()
