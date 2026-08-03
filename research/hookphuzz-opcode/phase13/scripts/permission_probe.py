#!/usr/bin/env python3
"""Make three redacted, local-only CF7 permission controls before replay."""
from __future__ import annotations
import argparse, html, json, os, re
import requests

ROUTE="http://localhost/wp-json/contact-form-7/v1/contact-forms"

def login() -> tuple[requests.Session, str]:
    session=requests.Session(); password=os.environ["PHASE13_LOCAL_PASSWORD"]
    session.get("http://localhost/wp-login.php",timeout=15)
    response=session.post("http://localhost/wp-login.php",data={"log":"phase13user","pwd":password,"wp-submit":"Log In","redirect_to":"http://localhost/wp-admin/","testcookie":"1"},allow_redirects=True,timeout=15)
    profile=session.get("http://localhost/wp-admin/profile.php",timeout=15)
    nonce=session.get("http://localhost/wp-admin/admin-ajax.php",params={"action":"rest-nonce"},timeout=15).text.strip()
    if response.status_code!=200 or profile.status_code!=200 or "wp-login.php" in profile.url or not any(c.name.startswith("wordpress_logged_in_") for c in session.cookies) or not nonce.isalnum() or len(nonce)<8: raise RuntimeError("fresh_local_authentication_failed")
    return session,nonce

def logout(session: requests.Session) -> None:
    profile=session.get("http://localhost/wp-admin/profile.php",timeout=15)
    match=re.search(r'href=["\']([^"\']*wp-login\.php\?action=logout[^"\']*)',profile.text)
    if not match: raise RuntimeError("local_logout_url_unavailable")
    session.get(html.unescape(match.group(1)).replace("&amp;","&"),timeout=15)

def send(session: requests.Session, request_id: str, *, nonce: str | None = None, params: dict[str,str] | None = None) -> int:
    headers={"X-HookPhuzz-Request-ID":request_id}
    if nonce: headers["X-WP-Nonce"]=nonce
    return session.get(ROUTE,headers=headers,params=params,timeout=15).status_code

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--anonymous-id",required=True); parser.add_argument("--invalid-id",required=True); parser.add_argument("--valid-id",required=True); parser.add_argument("--marker",required=True); args=parser.parse_args()
    anonymous=send(requests.Session(),args.anonymous_id)
    invalid_session,invalid_nonce=login(); logout(invalid_session); invalid=send(invalid_session,args.invalid_id,nonce=invalid_nonce)
    valid_session,valid_nonce=login(); params={"per_page":"10","offset":"0","order":"desc","orderby":"date","search":args.marker}; valid=send(valid_session,args.valid_id,nonce=valid_nonce,params=params)
    print(json.dumps({"route":"/contact-form-7/v1/contact-forms","method":"GET","anonymous":{"request_id":args.anonymous_id,"http_status":anonymous,"denied":anonymous==403},"invalidated_auth":{"request_id":args.invalid_id,"http_status":invalid,"denied":invalid==403},"valid_auth":{"request_id":args.valid_id,"http_status":valid,"accepted":valid==200,"current_run":True},"parameter_names":sorted(params),"authentication_material":"redacted"},sort_keys=True))
    return 0 if anonymous==403 and invalid==403 and valid==200 else 1

if __name__=="__main__": raise SystemExit(main())
