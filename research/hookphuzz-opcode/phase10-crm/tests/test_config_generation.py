import json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1]
class Config(unittest.TestCase):
 def test_bracket_serialization_from_artifact(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d); n={'entrypoint':{'name':'a','endpoint':'/x','method':'POST'},'callback':{'id':'C::m'},'parameters':[{'source':'POST','path':['a','b'],'confidence':'runtime_confirmed'}]};(d/'n').write_text(json.dumps(n));subprocess.run([sys.executable,ROOT/'collector/generate_config.py',d/'n','--out',d/'c','--summary',d/'s'],check=True);self.assertIn('a[b]',json.loads((d/'c').read_text())['body_params']['fuzz'])
   c=json.loads((d/'c').read_text()); self.assertNotIn('phase10admin',json.dumps(c)); self.assertIn('${PHASE10_RUNTIME_NONCE}',json.dumps(c))
