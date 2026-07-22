#!/usr/bin/env python3
import argparse,hashlib,json,re,zipfile
from pathlib import Path
EXPECTED=['per_page','offset','order','orderby','search']
def main():
 p=argparse.ArgumentParser();p.add_argument('--zip',required=True);p.add_argument('--out',required=True);p.add_argument('--md',required=True);a=p.parse_args();raw=Path(a.zip).read_bytes();digest=hashlib.sha256(raw).hexdigest()
 with zipfile.ZipFile(a.zip) as z:
  plugin=z.read('contact-form-7/wp-contact-form-7.php').decode('utf-8','replace');rest=z.read('contact-form-7/includes/rest-api.php').decode('utf-8','replace')
 version=re.search(r'^\s*\*?\s*Version:\s*(.+)$',plugin,re.M).group(1).strip();keys=[x for x in EXPECTED if re.search(r"get_param\(\s*'"+re.escape(x)+r"'\s*\)",rest)]
 if version!='5.7.7' or keys!=EXPECTED or "current_user_can( 'wpcf7_read_contact_forms' )" not in rest: raise SystemExit('pinned CF7 source contract failed')
 doc={'schema_version':1,'analysis_type':'source_analysis','plugin':{'slug':'contact-form-7','version':version,'archive_sha256':digest},'route':{'namespace':'contact-form-7/v1','path':'/contact-forms','method':'GET','callback_candidate':'WPCF7_REST_Controller::get_contact_forms','permission_contract':'current_user_can(wpcf7_read_contact_forms)'},'source_candidates':[{'name':x,'path':[x],'transport_source':'GET/query','access_mechanism':'WP_REST_Request::get_param','source_analysis_observed':True,'runtime_observed':False} for x in keys]}
 Path(a.out).write_text(json.dumps(doc,indent=2)+'\n');Path(a.md).write_text('# CF7 source-assisted analysis\n\n- Archive SHA-256: `'+digest+'`\n- Plugin: Contact Form 7 '+version+'\n- Route candidate: `GET /contact-form-7/v1/contact-forms`\n- Callback candidate: `WPCF7_REST_Controller::get_contact_forms`\n- Permission contract: `wpcf7_read_contact_forms`\n- Candidates: `'+ '`, `'.join(keys)+'`.\n\nSource candidates only. Runtime proof is in `normalized-params.json`.\n')
if __name__=='__main__':main()
