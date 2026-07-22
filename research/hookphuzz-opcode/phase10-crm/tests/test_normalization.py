import json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1]; NORMAL=ROOT/'collector/normalize_events.py'
class Normalization(unittest.TestCase):
 def test_nested_and_helper_attach(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d); op={'request_id':'r','events':[{'source':'POST','path':['root','leaf'],'operation':'read','filename':'/wp-content/plugins/x/a.php','callback_context':{'root_callback':'C::m'}}]}; helper={'request_id':'r','evidence_type':'helper_runtime','source':'REQUEST','path':['root'],'callback':'C::m'}; cb={'request_id':'r'}
   for n,v in [('o',op),('h',helper),('c',cb)]:(d/n).write_text(json.dumps(v))
   subprocess.run([sys.executable,NORMAL,'--opcode',d/'o','--helper',d/'h','--callback',d/'c','--plugin','x','--version','1','--action','a','--callback-id','C::m','--out',d/'n','--classification',d/'k'],check=True)
   self.assertEqual(json.loads((d/'n').read_text())['parameters'][0]['path'],['root','leaf'])
 def test_different_request_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d); [ (d/n).write_text(json.dumps(v)) for n,v in [('o',{'request_id':'a','events':[]}),('h',{'request_id':'b'}),('c',{'request_id':'a'})] ]
   self.assertNotEqual(subprocess.run([sys.executable,NORMAL,'--opcode',d/'o','--helper',d/'h','--callback',d/'c','--plugin','x','--version','1','--action','a','--callback-id','C::m','--out',d/'n','--classification',d/'k']).returncode,0)
 def test_duplicate_and_wrong_callback_excluded(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d); event={'source':'POST','path':['root','leaf'],'operation':'read','filename':'/wp-content/plugins/x/a.php','callback_context':{'root_callback':'C::m'}}; op={'request_id':'r','events':[event,event,dict(event,callback_context={'root_callback':'Else::m'})]}
   for n,v in [('o',op),('h',{'request_id':'r'}),('c',{'request_id':'r'})]:(d/n).write_text(json.dumps(v))
   subprocess.run([sys.executable,NORMAL,'--opcode',d/'o','--helper',d/'h','--callback',d/'c','--plugin','x','--version','1','--action','a','--callback-id','C::m','--out',d/'n','--classification',d/'k'],check=True)
   self.assertEqual(len(json.loads((d/'n').read_text())['parameters']),1)
