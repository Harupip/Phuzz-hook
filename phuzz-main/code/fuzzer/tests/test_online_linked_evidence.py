import json
import subprocess
import unittest
from types import SimpleNamespace


from hook_energy.seed_generation.online_linked_evidence import RuntimeBatchTimeout, read_runtime_batch


class RuntimeBatchReaderTests(unittest.TestCase):
    def test_raw_payload_transport_preserves_large_integer(self):
        payload = {"value": 18446744073709551617, "object": {}, "array": []}
        envelope = {"pairs": [{"request_name": "r.json", "zend_name": "r.json",
                              "request_json": json.dumps(payload), "zend_json": "{}"}]}
        result = read_runtime_batch(run_id="run", plugin_slug="fixture", timeout=1,
            run_command=lambda *args, **kwargs: SimpleNamespace(
                returncode=0, stdout=json.dumps(envelope), stderr=""))
        self.assertEqual(result["pairs"][0]["request"], payload)

    def test_reads_one_typed_envelope_with_exact_run_and_plugin_arguments(self):
        calls = []
        envelope = {
            "pairs": [{
                "request_name": "request-1.json",
                "request": {
                    "request_id": "request-1",
                    "legacy_run_id": "run-1",
                    "target_plugin": "fixture",
                    "request_params": {
                        "json_params": {
                            "object": {},
                            "array": [],
                            "flag": False,
                            "zero": 0,
                            "nil": None,
                        }
                    },
                },
                "zend_name": "request-1.json",
                "zend": {"request_id": "request-1", "run_id": "run-1"},
            }],
            "stats": {"file_count": 601, "paired_count": 1},
        }

        expected = json.loads(json.dumps(envelope))
        for pair in envelope["pairs"]:
            pair["request_json"] = json.dumps(pair.pop("request"))
            pair["zend_json"] = json.dumps(pair.pop("zend"))

        def run_command(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")

        result = read_runtime_batch(
            run_id="run-1;unexpected",
            plugin_slug="fixture && unexpected",
            timeout=1.25,
            run_command=run_command,
        )

        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[:6], ["docker", "compose", "exec", "-T", "web", "php"])
        self.assertEqual(command[6:11], ["-d", "display_errors=0", "-d", "log_errors=1", "-r"])
        self.assertEqual(command[12:], ["--", "run-1;unexpected", "fixture && unexpected"])
        self.assertNotIn("shell", kwargs)
        self.assertLessEqual(kwargs["timeout"], 1.25)
        self.assertEqual(result, expected)
        self.assertIsInstance(result["pairs"][0]["request"]["request_params"]["json_params"]["object"], dict)
        self.assertEqual(result["pairs"][0]["request"]["request_params"]["json_params"]["array"], [])
        self.assertIs(result["pairs"][0]["request"]["request_params"]["json_params"]["flag"], False)
        self.assertEqual(result["pairs"][0]["request"]["request_params"]["json_params"]["zero"], 0)
        self.assertIsNone(result["pairs"][0]["request"]["request_params"]["json_params"]["nil"])

    def test_rejects_malformed_output_nonzero_exit_and_timeout(self):
        cases = (
            (SimpleNamespace(returncode=0, stdout="not-json", stderr=""), "RUNTIME_BATCH_INVALID_OUTPUT"),
            (SimpleNamespace(returncode=0, stdout=json.dumps({"pairs": {}}), stderr=""), "RUNTIME_BATCH_INVALID_OUTPUT"),
            (SimpleNamespace(returncode=7, stdout="", stderr="docker failed"), "RUNTIME_BATCH_FAILED"),
        )
        for result, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(RuntimeError, reason):
                    read_runtime_batch(
                        run_id="run",
                        plugin_slug="fixture",
                        timeout=2,
                        run_command=lambda command, **kwargs: result,
                    )

        def timeout_runner(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with self.assertRaisesRegex(RuntimeBatchTimeout, "RUNTIME_BATCH_TIMEOUT"):
            read_runtime_batch(
                run_id="run",
                plugin_slug="fixture",
                timeout=0.5,
                run_command=timeout_runner,
            )


if __name__ == "__main__":
    unittest.main()
