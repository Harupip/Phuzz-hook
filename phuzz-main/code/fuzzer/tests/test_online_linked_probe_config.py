import json
import tempfile
import unittest
from pathlib import Path

from online_linked.coordination.errors import OnlineLinkedError
from online_linked.coordination.probe_config import (
    load_correlated_probe_artifacts,
    probe_paths,
    probe_request_row,
    probe_runtime_metadata,
    select_probe_item,
)


def item(variant, **seed):
    return {"seed": {"seed_variant_id": variant, **seed}}


class SelectProbeItemTests(unittest.TestCase):
    def test_select_probe_item_matches_variant_then_single_fallback(self):
        """The probe must replay the exported seed for its own variant; a lone item is the only
        safe fallback, and an ambiguous or malformed report yields no config at all."""
        a, b = item("a"), item("b")
        self.assertIs(select_probe_item({"merged_suggested_seeds": {"suggested_seeds": [a, b]}},
                                        {"seed_variant_id": "b"}), b)
        self.assertIs(select_probe_item({"merged_suggested_seeds": {"suggested_seeds": [a]}},
                                        {"seed_variant_id": "other"}), a)
        self.assertIsNone(select_probe_item({"merged_suggested_seeds": {"suggested_seeds": [a, b]}},
                                            {"seed_variant_id": "c"}))
        self.assertIsNone(select_probe_item({"merged_suggested_seeds": {"suggested_seeds": a}},
                                            {"seed_variant_id": "a"}))


class ProbeRuntimeMetadataTests(unittest.TestCase):
    def test_probe_metadata_redacts_candidate_value(self):
        """Probe configs are published artifacts: they name the candidate field but never carry
        its observed value, and the source is normalized like every other parameter key."""
        metadata = probe_runtime_metadata({"name": "n", "source": "post", "location": "form",
                                           "helper_depth": 2, "request_id": "r", "run_id": "w"})
        self.assertEqual(metadata["source"], "POST")
        self.assertEqual(metadata["value_origin"], "generated_probe")
        self.assertIs(metadata["candidate_value_redacted"], True)
        self.assertEqual((metadata["candidate_request_id"], metadata["candidate_run_id"]), ("r", "w"))


class ProbePathsTests(unittest.TestCase):
    def test_probe_paths_are_stable(self):
        """Operators and the exporter find probe artifacts by these paths; moving code must not
        move the files."""
        paths = probe_paths(run_dir=Path("r"), config_dir=Path("c"), version="v2", probe_id="p3")
        self.assertEqual(paths.replay, Path("c/versions/v2/probe/p3/p3-replay.json"))
        self.assertEqual(paths.replay_mirror, Path("r/versions/v2/probe/p3/p3-replay.json"))
        self.assertEqual(paths.config, Path("c/versions/v2/probe/p3/p3-config.json"))
        self.assertEqual(paths.config_mirror, Path("r/versions/v2/probe/p3/p3-config.json"))
        self.assertEqual(paths.root, Path("r/versions/v2/probe/p3"))
        self.assertEqual(paths.generated_dir, Path("c/versions/v2/probe/p3/exported"))
        self.assertEqual(paths.generated_summary, Path("r/versions/v2/probe/p3/generated_config_summary.json"))


class ProbeRequestRowTests(unittest.TestCase):
    def test_get_to_post_transition_switches_probe_parent_method(self):
        """A GET->POST probe proves fields of the POST request, so admission must judge it
        against a POST parent; the row's slug is how the sender locates the replay config."""
        parent = {"hook_name": "h", "callback_id": "cb", "entrypoint_type": "ajax", "resolved_method": "GET"}
        probe_item = item("v", method_transition={"from": "GET", "to": "POST"}, method="POST")
        row, probe_parent, transition = probe_request_row(
            probe_item, parent, replay_path=Path("root/c/versions/v1/probe/p1/p1-replay.json"),
            config_root=Path("root"),
        )
        self.assertIs(transition, True)
        self.assertEqual(probe_parent["resolved_method"], "POST")
        self.assertEqual(parent["resolved_method"], "GET")
        self.assertEqual(row["config_slug"], "c/versions/v1/probe/p1/p1-replay")
        self.assertEqual((row["resolved_method"], row["seed_variant_id"], row["hook_name"]), ("POST", "v", "h"))
        _, same_parent, transition = probe_request_row(
            item("v"), parent, replay_path=Path("root/x.json"), config_root=Path("root"),
        )
        self.assertIs(transition, False)
        self.assertIs(same_parent, parent)


class CorrelatedArtifactsTests(unittest.TestCase):
    def write(self, path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_correlated_artifacts_require_matching_run_id(self):
        """A probe is only evidence if both artifacts belong to the run that sent it; anything
        else, including a path escaping the request directory, is a correlation failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request_dir, zend_dir = root / "request", root / "zend"
            self.write(request_dir / "x.json", {"request_id": "x", "legacy_run_id": "run-p1"})
            self.write(zend_dir / "x.json", {"request_id": "x", "run_id": "run-p1"})
            request_path, request, zend_path, zend = load_correlated_probe_artifacts(
                request_dir, zend_dir, "x.json", "run-p1",
            )
            self.assertEqual((request_path, zend_path.name), (request_dir / "x.json", "x.json"))
            self.assertEqual((request["request_id"], zend["run_id"]), ("x", "run-p1"))

            self.write(zend_dir / "x.json", {"request_id": "x", "run_id": "other"})
            with self.assertRaisesRegex(OnlineLinkedError, "PROBE_ARTIFACT_CORRELATION_FAILED"):
                load_correlated_probe_artifacts(request_dir, zend_dir, "x.json", "run-p1")
            with self.assertRaisesRegex(OnlineLinkedError, "PROBE_ARTIFACT_CORRELATION_FAILED"):
                load_correlated_probe_artifacts(request_dir, zend_dir, "../x.json", "run-p1")


if __name__ == "__main__":
    unittest.main()
