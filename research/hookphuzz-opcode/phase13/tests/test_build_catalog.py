from __future__ import annotations
import importlib.util, unittest
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'scripts'/'build_catalog.py'; S=importlib.util.spec_from_file_location('catalog',P); M=importlib.util.module_from_spec(S); S.loader.exec_module(M)
BASE={'schema_version':1,'run_id':'r','plugin_slug':'p','plugin_version':'1','routes':[{'route':'/p/v1/x','methods':{'GET':True,'POST':True},'callback_repr':'p_cb','source_file':'/wp-content/plugins/p/x.php','permission_callback':'perm','permission_source_file':'/wp-content/plugins/p/x.php','argument_definitions':{'q':{'type':'string'}}}]}
class CatalogTests(unittest.TestCase):
 def test_no_fallback(self): self.assertEqual(M.methods({}),[])
 def test_methods_sorted(self): self.assertEqual(M.methods({'POST':True,'GET':True}),['GET','POST'])
 def test_stale(self):
  with self.assertRaisesRegex(ValueError,'stale'): M.normalize(BASE,'other','p','1')
 def test_slug(self):
  with self.assertRaisesRegex(ValueError,'cross'): M.normalize(BASE,'r','other','1')
 def test_version(self):
  with self.assertRaisesRegex(ValueError,'version'): M.normalize(BASE,'r','p','2')
 def test_owner(self): self.assertEqual(M.owner('/wp-content/plugins/p/a.php','p')[0],'plugin')
 def test_core(self): self.assertEqual(M.owner('/wp-includes/a.php','p')[0],'wordpress_core')
 def test_permission_separate(self): self.assertNotEqual(M.normalize(BASE,'r','p','1')['records'][0]['callback'],M.normalize(BASE,'r','p','1')['records'][0]['permission_callback'])
 def test_schema_not_runtime(self): self.assertEqual(M.normalize(BASE,'r','p','1')['records'][0]['schema_parameters'][0]['parameter_origin'],'schema')
 def test_deterministic(self): self.assertEqual(M.normalize(BASE,'r','p','1'),M.normalize(BASE,'r','p','1'))
 def test_duplicate(self):
  x={**BASE,'routes':BASE['routes']*2}; self.assertEqual(len(M.normalize(x,'r','p','1')['records']),1)
 def test_malformed(self):
  with self.assertRaisesRegex(ValueError,'malformed'): M.normalize({'schema_version':1},'r','p','1')
 def test_secret_absent(self): self.assertNotIn('cookie',str(M.normalize(BASE,'r','p','1')).lower())
 def test_route_path_count(self): self.assertEqual(M.normalize(BASE,'r','p','1')['metrics']['route_path_count'],1)
 def test_endpoint_count(self): self.assertEqual(M.normalize(BASE,'r','p','1')['metrics']['normalized_endpoint_count'],1)
 def test_distinct_same_path(self):
  x={**BASE,'routes':[BASE['routes'][0],{**BASE['routes'][0],'callback_repr':'other'}]}; self.assertEqual(M.normalize(x,'r','p','1')['metrics']['normalized_endpoint_count'],2)
 def test_missing_callback_limited(self):
  x={**BASE,'routes':[{**BASE['routes'][0],'callback_repr':None}]}; self.assertIn('missing_callback',M.normalize(x,'r','p','1')['records'][0]['limitations'])
 def test_other_plugin(self): self.assertEqual(M.owner('/wp-content/plugins/other/a.php','p')[0],'unrelated_plugin')
 def test_unsupported_marker(self): self.assertEqual(M.safe(object())['unsupported'],'object')
 def test_runtime_empty(self): self.assertEqual(M.normalize(BASE,'r','p','1')['records'][0]['runtime_parameters'],[])
 def test_sha_is_deterministic_identity(self): self.assertEqual(M.normalize(BASE,'r','p','1')['records'][0]['endpoint_identity'],M.normalize(BASE,'r','p','1')['records'][0]['endpoint_identity'])
 def test_namespace(self): self.assertEqual(M.namespace('/wc/store/v1/products'),'wc/store/v1')
 def test_parameter_isolation(self): self.assertEqual(M.normalize(BASE,'r','p','1')['records'][0]['parameter_origins'],['schema'])
if __name__=='__main__': unittest.main()
