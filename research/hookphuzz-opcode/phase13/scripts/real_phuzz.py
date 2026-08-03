#!/usr/bin/env python3
"""Run one benign generated config through the production PHUZZ request path."""
from __future__ import annotations
import argparse, hashlib, html, inspect, json, os, re, sys
from pathlib import Path
import requests

sys.path.insert(0, "/hookphuzz-fuzzer")
from fuzzer import Fuzzer

def redacted(prepared: requests.PreparedRequest) -> dict[str, object]:
    return {"method": prepared.method, "url": prepared.url, "headers": sorted(k for k in prepared.headers if k.lower() not in {"cookie", "x-wp-nonce", "authorization"}), "cookies_present": "Cookie" in prepared.headers, "nonce_header_present": "X-WP-Nonce" in prepared.headers, "content_type": prepared.headers.get("Content-Type", ""), "body_present": bool(prepared.body)}

def rest_error_code(response: requests.Response) -> str | None:
    try:
        value = response.json()
    except ValueError:
        return None
    return value.get("code") if isinstance(value, dict) and isinstance(value.get("code"), str) else None

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("config"); p.add_argument("--request-id", required=True); group=p.add_mutually_exclusive_group(); group.add_argument("--auth", action="store_true"); group.add_argument("--invalid-auth", action="store_true"); args=p.parse_args()
    path=Path(args.config); before=hashlib.sha256(path.read_bytes()).hexdigest(); f=Fuzzer("phase13", config_only=True)
    f.load_config(path.stem, str(path.parent)); f.config.setdefault("headers", {"data": []})
    f.config["headers"]["data"].append({"name":"X-HookPhuzz-Request-ID","value":args.request_id}); f.config["headers"]["fixed"]=["^X-HookPhuzz-Request-ID$"]
    session=requests.Session(); auth={"cookie_present":False,"nonce_present":False}
    if args.auth or args.invalid_auth:
        password=os.environ["PHASE13_LOCAL_PASSWORD"]
        session.get("http://localhost/wp-login.php", timeout=15)
        login=session.post("http://localhost/wp-login.php",data={"log":"phase13user","pwd":password,"wp-submit":"Log In","redirect_to":"http://localhost/wp-admin/","testcookie":"1"},allow_redirects=True,timeout=15)
        profile=session.get("http://localhost/wp-admin/profile.php", timeout=15)
        nonce=session.get("http://localhost/wp-admin/admin-ajax.php",params={"action":"rest-nonce"},timeout=15).text.strip()
        logged_in=any(cookie.name.startswith("wordpress_logged_in_") for cookie in session.cookies)
        if login.status_code != 200 or profile.status_code != 200 or "wp-login.php" in profile.url or not logged_in or not nonce.isalnum() or len(nonce) < 8: raise RuntimeError("fresh local authentication failed")
        cookies=session.cookies.get_dict()
        f.config["headers"]["data"].append({"name":"X-WP-Nonce","value":nonce})
        f.config["headers"]["fixed"]=["^X-WP-Nonce$"]
        f.config["cookies"]={"data":[{"name":k,"value":v} for k,v in cookies.items()],"fixed":[".*"]}
        auth={"cookie_present":True,"nonce_present":True,"invalidated":False}
        if args.invalid_auth:
            match=re.search(r'href=["\']([^"\']*wp-login\.php\?action=logout[^"\']*)', profile.text)
            if not match: raise RuntimeError("local logout URL unavailable")
            session.get(html.unescape(match.group(1)).replace("&amp;", "&"), timeout=15)
            auth["invalidated"]=True
    f.load_request_data(); candidate=next(f.generate_initial_candidates()); prepared=f.prepare_request(candidate)
    response=session.send(prepared,timeout=15,allow_redirects=False)
    after=hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps({"loaded_by":"Fuzzer.load_config","prepared_by":"Fuzzer.prepare_request","production_module_path":inspect.getfile(Fuzzer),"callable_identity":"fuzzer.Fuzzer","candidate_created":True,"coverage_id":candidate.coverage_id,"request_id":args.request_id,"config_request_id":f.config.get("metadata",{}).get("request_id"),"http_status":response.status_code,"rest_error_code":rest_error_code(response),"config_path":str(path),"config_sha256":before,"config_hash_preserved":before==after,"prepared_request":redacted(prepared),"parameter_names":sorted(set(re.findall(r'(?:[?&])([^=&]+)=',prepared.url))),"authentication":auth},sort_keys=True))
    return 0
if __name__ == "__main__": raise SystemExit(main())
