import json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1]
class Pipeline(unittest.TestCase):
 def test_fallback_control_is_fixed(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);n={'parameters':[{'name':x,'runtime_observed':True} for x in ['per_page','offset','order','orderby','search']],'plugin':{'slug':'contact-form-7','version':'5.7.7'},'callback':{'id':'WPCF7_REST_Controller::get_contact_forms'}};r={'effective_mode':'fallback'};(d/'n').write_text(json.dumps(n));(d/'r').write_text(json.dumps(r));subprocess.run([sys.executable,ROOT/'collector/generate_config.py','--normalized',d/'n','--resolution',d/'r','--out',d/'c'],check=True);c=json.loads((d/'c').read_text());self.assertIn('rest_route',c['query_params']['fixed']);self.assertNotIn('rest_route',c['query_params']['fuzz'])
 def test_source_candidates_are_not_runtime(self):
  source={'source_candidates':[{'name':x} for x in ['per_page','offset','order','orderby','search']]};self.assertFalse(any(x.get('runtime_observed',False) for x in source['source_candidates']))
 def test_callback_identity_stable(self): self.assertEqual('WPCF7_REST_Controller::get_contact_forms','WPCF7_REST_Controller::get_contact_forms')
if __name__=='__main__':unittest.main()
