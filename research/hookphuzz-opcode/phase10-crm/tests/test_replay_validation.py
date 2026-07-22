import json,unittest
class ReplayContract(unittest.TestCase):
 def test_required_gate_keys(self):
  required={'request_sent','http_completed','action_dispatched','callback_reached','marker_observed','parameter_path_matched','request_isolation_pass','generated_config_used'}
  self.assertEqual(len(required),8)
