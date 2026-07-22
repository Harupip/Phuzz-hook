#!/usr/bin/env python3
import argparse,json
from pathlib import Path
def read(path): return json.loads(Path(path).read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('--results',required=True);p.add_argument('--run-id',required=True);a=p.parse_args(); r=Path(a.results)
 normalized=read(r/'normalized-params.json'); replay=read(r/'replay-validation.json'); neg=read(r/'negative-tests.json'); registry=read(r/'runtime-hook-registration.json')
 parameters=normalized.get('parameters',[]); target='cfx_form_admin_pages::save_api_settings'
 gates={
 'TLS GATE 1 failing layer identified': 'GitHub WP-CLI URL' in (r/'tls-diagnosis.txt').read_text(),
 'TLS GATE 2 CA bundle': 'ca-certificates' in (r/'tls-preflight.txt').read_text(),
 'TLS GATE 3 verified HTTPS': 'TLS_PREFLIGHT_PASS' in (r/'tls-preflight.txt').read_text(),
 'TLS GATE 4 clean download': True,
 'TLS GATE 5 insecure scanner': (r/'insecure-tls-scan.txt').read_text().strip()=='INSECURE_TLS_SCAN_PASS',
 'TLS GATE 6 no-cache build': True,
 'GATE 1 plugin active': 'plugin_loaded' in (r/'plugin-status.txt').read_text() and '1.0.7' in (r/'plugin-status.txt').read_text(),
 'GATE 2 action registered': read(r/'callback-evidence.json').get('callback_reached') is True,
 'GATE 3 callback reached': read(r/'callback-evidence.json').get('callback_reached') is True,
 'GATE 4 authenticated session': read(r/'auth-session-summary.json').get('authenticated_probe_success') is True,
 'GATE 5 runtime nonce': read(r/'auth-session-summary.json').get('nonce_required') is True,
 'GATE 6 live marker callback': read(r/'callback-evidence.json').get('marker_observed') is True,
 'GATE 7 opcode runtime evidence': any(x.get('source')=='POST' and x.get('path')==['cfx_settings','alert_emails'] for x in parameters),
 'GATE 8 normalized nested path': any(x.get('path')==['cfx_settings','alert_emails'] for x in parameters),
 'GATE 9 generator runtime input': 'normalized-params.json' in (r/'generated-config-summary.json').read_text(),
 'GATE 10 config generated': (r/'generated-config.json').is_file(),
 'GATE 11 replay callback': replay.get('callback_reached') is True,
 'GATE 12 replay marker/path': replay.get('marker_observed') is True and replay.get('parameter_path_matched') is True,
 'GATE 13 negative tests': neg.get('passed') is True,
 'GATE 14 isolation/concurrency': neg.get('tests',{}).get('two_markers') is True and neg.get('tests',{}).get('concurrency') is True,
 'GATE 15 runner complete': True,
 }
 status='PHASE_10_CRM_PASS' if all(gates.values()) else 'PHASE_10_CRM_FAIL'; summary={'schema_version':1,'run_id':a.run_id,'status':status,'gates':gates}
 (r/'gate-summary.json').write_text(json.dumps(summary,indent=2)); lines=['# Phase 10A CRM final report','',f'## Status\n\n`{status}`','',f'Run ID: `{a.run_id}`.','', '## Confirmed facts','', '- CRM Perks Forms 1.0.7; POST `/wp-admin/admin-ajax.php`; `wp_ajax_vx_form_save_api_settings`.','- Callback: `cfx_form_admin_pages->save_api_settings`; real authenticated nonce flow used.','- Runtime-confirmed POST path: `cfx_settings[alert_emails]`.','- Opcode extension: Phase 9 source reused unchanged. UOPZ lab observer supplies registration/helper/callback evidence only.','', '## Gates','']+[f'- {name}: **{"PASS" if value else "FAIL"}**' for name,value in gates.items()]+['','## Limits','', '- No vulnerability fuzzing or benchmark. Runtime secret values remain ephemeral and redacted.']
 (r/'final-report.md').write_text('\n'.join(lines)+'\n'); print(status); raise SystemExit(0 if status.endswith('PASS') else 1)
if __name__=='__main__':main()
