from __future__ import annotations
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from phase12_schema import initial_value, normalize_route

class Phase12SchemaTests(unittest.TestCase):
    def test_path_and_schema_only_locations(self):
        rows = normalize_route({"namespace":"demo/v1","route":"/items/(?P<id>\\d+)","methods":"PUT,PATCH","argument_definitions":{"id":{"type":"integer","required":True},"name":{"type":"string"}}})
        self.assertEqual([r["method"] for r in rows], ["PUT", "PUT", "PATCH", "PATCH"])
        self.assertEqual(rows[0]["parameter"]["location"], "path")
        self.assertEqual(rows[1]["parameter"]["location_candidates"], ["query", "json", "form"])
    def test_seeds_keep_types_and_block_unsupported(self):
        self.assertEqual(initial_value({"type":"boolean"})["seed"], True)
        self.assertEqual(initial_value({"type":"number"})["seed"], 1.0)
        self.assertEqual(initial_value({"type":"string","pattern":".*"})["seed_status"], "unsupported")
    def test_method_specific_inputs_are_not_merged(self):
        put = normalize_route({"route":"/x","methods":"PUT","argument_definitions":{"name":{"required":True,"type":"string"}}})[0]
        patch = normalize_route({"route":"/x","methods":"PATCH","argument_definitions":{"name":{"required":False,"type":"string"}}})[0]
        self.assertTrue(put["parameter"]["required"]); self.assertFalse(patch["parameter"]["required"])
if __name__ == "__main__": unittest.main()
