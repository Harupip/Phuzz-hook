#!/usr/bin/env python3
import argparse,re,json
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--plugin',required=True);p.add_argument('--out',required=True);p.add_argument('--nonce-out');p.add_argument('--ajax-out');p.add_argument('--admin-out');p.add_argument('--contract-out');a=p.parse_args(); root=Path(a.plugin); mainf=root/'crm-perks-forms.php'; admin=root/'includes/admin-pages.php'; template=root/'templates/settings.php'
 version=re.search(r'^\s*\*?\s*Version:\s*(.+)$',mainf.read_text(errors='replace'),re.M); body=admin.read_text(errors='replace'); hook=re.search(r"add_action\(\s*['\"](wp_ajax_[^'\"]+)['\"]\s*,\s*array\(\$this\s*,\s*['\"]([^'\"]+)",body)
 start=body.find('public function save_api_settings()'); end=body.find('/**', start); method=body[start:end]
 nonce=re.search(r"check_ajax_referer\(['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)",method)
 if not(version and hook and start >= 0 and nonce and "$_POST['cfx_settings']['alert_emails']" in method): raise SystemExit('source hypotheses not verified')
 def line(s,needle): return s[:s.index(needle)].count('\n')+1
 settings=template.read_text(errors='replace'); callback_line=line(body,'public function save_api_settings'); action,field=nonce.group(1),nonce.group(2); admin_url='/wp-admin/admin.php?page=cfx-form&tab=settings'
 text='\n'.join(['# CRM Perks Forms source analysis','',f'- Plugin/version: CRM Perks Forms {version.group(1).strip()}',f'- AJAX registration: `includes/admin-pages.php:{line(body,hook.group(0))}`',f'- Hook: `{hook.group(1)}`',f'- Callback: object method `cfx_form_admin_pages->{hook.group(2)}`',f'- Callback body: `includes/admin-pages.php:{callback_line}`', '- Endpoint/method: `POST /wp-admin/admin-ajax.php`','- Authentication: `current_user_can(cfx_form::$id . "_edit_settings")`.','- Nonce: `check_ajax_referer(\''+action+'\', \''+field+'\')`.','- Input: `cfx_form::post(\'cfx_settings\')` reads `$_REQUEST`; callback directly reads `$_POST[\'cfx_settings\'][\'alert_emails\']`.',f'- Form field evidence: `templates/settings.php:{line(settings,"cfx_settings[alert_emails]")}`.'])+'\n'
 Path(a.out).write_text(text)
 contract={'nonce_required':True,'verification_function':'check_ajax_referer','nonce_action':action,'request_field':field,'callback_source':'includes/admin-pages.php:'+str(callback_line),'admin_url':admin_url,'value_source':{'type':'hidden_input','template':'templates/settings.php','field':field}}
 if a.contract_out: Path(a.contract_out).write_text(json.dumps(contract,indent=2))
 if a.nonce_out: Path(a.nonce_out).write_text('# Nonce source analysis\n\n- nonce_required=true; check: `check_ajax_referer(\''+action+'\', \''+field+'\')` at `includes/admin-pages.php:'+str(callback_line+1)+'`.\n- Capability: `cfx_form_edit_settings`; failure uses WordPress `check_ajax_referer` default `wp_die(-1)`.\n- Token creation: `wp_create_nonce("'+action+'")` in `templates/settings.php:'+str(line(settings,'wp_create_nonce'))+'`; hidden request field `'+field+'`.\n')
 if a.ajax_out: Path(a.ajax_out).write_text('# AJAX client analysis\n\n- Inline client: `templates/settings.php:'+str(line(settings,'$("#crm-sales-settings")'))+'`.\n- Serializes `#crm-sales-settings`, appends `action='+hook.group(1).removeprefix('wp_ajax_')+'`, posts to `ajaxurl`.\n- Nonce is form hidden field `'+field+'`; no localized nonce object.\n')
 if a.admin_out: Path(a.admin_out).write_text(json.dumps({'menu_registration_file':'includes/admin-pages.php','page_slug':'cfx-form','capability':'cfx_form_read_settings','admin_url':admin_url,'enqueue_hook':'admin_enqueue_scripts','expected_script_handles':['cfx_form_admin']},indent=2))
if __name__=='__main__':main()
