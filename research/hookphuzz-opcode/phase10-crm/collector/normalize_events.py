#!/usr/bin/env python3
"""Fail-closed runtime-event normalizer. No CRM parameter constants."""
import argparse, json
from pathlib import Path

def load(path):
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict): raise ValueError(f'{path}: object required')
    return value

def main():
    p=argparse.ArgumentParser(); p.add_argument('--opcode',required=True); p.add_argument('--helper',required=True); p.add_argument('--callback',required=True); p.add_argument('--plugin',required=True); p.add_argument('--version',required=True); p.add_argument('--action',required=True); p.add_argument('--callback-id',required=True); p.add_argument('--out',required=True); p.add_argument('--classification',required=True); a=p.parse_args()
    op, helper, callback=load(a.opcode), load(a.helper), load(a.callback)
    rid=op.get('request_id')
    if not isinstance(rid,str) or helper.get('request_id')!=rid or callback.get('request_id')!=rid: raise SystemExit('request_id mismatch')
    target=a.callback_id.lower(); params=[]; classifications=[]; seen=set()
    for e in op.get('events',[]):
        ctx=e.get('callback_context') or {}; path=e.get('path') or []; source=e.get('source')
        in_target=str(ctx.get('root_callback') or '').lower()==target
        plugin_file='/wp-content/plugins/'+a.plugin+'/' in str(e.get('filename',''))
        # The Phase 9 opcode artifact may omit filename; an attributed target frame is
        # sufficient provenance. Unattributed reads remain bootstrap noise.
        cls='plugin_parameter' if in_target and e.get('operation')=='read' and source in {'GET','POST','REQUEST','COOKIE'} and path else ('wordpress_bootstrap' if not in_target else 'unknown')
        classifications.append({'source':source,'path':path,'classification':cls,'callback_context':ctx})
        if cls!='plugin_parameter': continue
        key=(source,tuple(map(str,path)))
        if key in seen: continue
        seen.add(key)
        evidence=[{'type':'opcode_runtime','artifact':'raw-opcode-events.json'}]
        # Helper evidence attaches only under same request and callback/root relationship.
        hp=helper.get('path') or []
        if helper.get('evidence_type')=='helper_runtime' and helper.get('callback','').lower()==target and path[:len(hp)]==hp:
            evidence.append({'type':'helper_runtime','artifact':'raw-helper-events.json','root_source':helper.get('source')})
        params.append({'source':source,'path':path,'encoding':'application/x-www-form-urlencoded','evidence':evidence,'confidence':'runtime_confirmed'})
    Path(a.classification).write_text(json.dumps({'schema_version':1,'request_id':rid,'events':classifications},indent=2))
    doc={'schema_version':1,'plugin':{'slug':a.plugin,'version':a.version},'entrypoint':{'type':'wp_ajax','name':a.action,'endpoint':'/wp-admin/admin-ajax.php','method':'POST'},'callback':{'id':a.callback_id,'display_name':a.callback_id.replace('::','->'),'source_file':'includes/admin-pages.php'},'parameters':params}
    Path(a.out).write_text(json.dumps(doc,indent=2))
    if not params: raise SystemExit('no runtime-confirmed plugin parameters')
if __name__=='__main__': main()
