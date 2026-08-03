#!/usr/bin/env python3
"""Normalize one immutable Phase 13 registry artifact without replaying it."""
from __future__ import annotations
import argparse, hashlib, json, re
from collections import Counter
from pathlib import Path
from typing import Any

VALID={"GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"}
def read(path:Path)->dict[str,Any]:
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict) or value.get("schema_version")!=1 or not isinstance(value.get("routes"),list): raise ValueError("malformed_registry_artifact")
    return value
def methods(value:Any)->list[str]:
    if not isinstance(value,dict): return []
    return sorted(key.upper() for key,enabled in value.items() if str(key).upper() in VALID and enabled is True)
def kind(value:Any)->str:
    text=str(value or "")
    if not text:return "unresolved"
    if "::" in text:return "static_method"
    return "function"
def owner(source:Any,slug:str)->tuple[str,list[str]]:
    text=str(source or "")
    root=f"/wp-content/plugins/{slug}/"
    if root in text:return "plugin",["callback_file_under_selected_plugin"]
    if "/wp-includes/" in text:return "wordpress_core",["callback_file_under_wp_includes"]
    if "/wp-content/plugins/" in text:return "unrelated_plugin",["callback_file_under_other_plugin"]
    return "unresolved",["callback_file_unresolved"]
def namespace(route:str)->str|None:
    match=re.match(r"^/((?:[^/]+/){1,2}v\d+)(?:/|$)",route)
    return match.group(1) if match else None
def safe(value:Any, depth:int=0)->Any:
    if depth>12:return {"unsupported":"depth_limit"}
    if value is None or isinstance(value,(bool,int,float,str)):return value
    if isinstance(value,list):return [safe(v,depth+1) for v in value]
    if isinstance(value,dict):return {str(k):safe(v,depth+1) for k,v in sorted(value.items())}
    return {"unsupported":type(value).__name__}
def parameter(name:str,value:Any)->dict[str,Any]:
    data=value if isinstance(value,dict) else {}
    unsupported=[key for key,value in data.items() if isinstance(value,dict) and "unsupported" in value]
    return {"name":name,"parameter_origin":"schema" if data else "unresolved","required":data.get("required") if "required" in data else None,"type":data.get("type") if "type" in data else None,"default":safe(data.get("default")) if "default" in data else None,"enum":safe(data.get("enum")) if "enum" in data else None,"description":data.get("description") if isinstance(data.get("description"),str) else None,"validate_callback":safe(data.get("validate_callback")) if "validate_callback" in data else None,"sanitize_callback":safe(data.get("sanitize_callback")) if "sanitize_callback" in data else None,"unsupported_value_markers":unsupported,"limitations":["unsupported_schema_value"] if unsupported else []}
def normalize(registry:dict[str,Any], expected_run:str, expected_slug:str, expected_version:str)->dict[str,Any]:
    if registry.get("schema_version")!=1 or not isinstance(registry.get("routes"),list): raise ValueError("malformed_registry_artifact")
    if registry.get("run_id")!=expected_run: raise ValueError("stale_registry_run_id")
    if registry.get("plugin_slug")!=expected_slug: raise ValueError("cross_plugin_registry_artifact")
    if registry.get("plugin_version")!=expected_version: raise ValueError("registry_plugin_version_mismatch")
    records=[]
    for raw in registry["routes"]:
        if not isinstance(raw,dict): records.append({"limitations":["malformed_registry_entry"]}); continue
        route=raw.get("route")
        if not isinstance(route,str) or not route.startswith("/"): records.append({"limitations":["malformed_route"]}); continue
        resolved=methods(raw.get("methods")); callback=raw.get("callback_repr")
        classification,evidence=owner(raw.get("source_file"),expected_slug)
        params=[parameter(str(k),v) for k,v in sorted((raw.get("argument_definitions") or {}).items())]
        limits=(["missing_method" if not resolved else "missing_callback"] if not resolved or not callback else [])
        if raw.get("callback_limitation"): limits.append(str(raw["callback_limitation"]))
        if raw.get("permission_limitation"): limits.append("permission_"+str(raw["permission_limitation"]))
        identity=hashlib.sha256(json.dumps([route,resolved,callback,raw.get("permission_callback"),params],sort_keys=True,default=str).encode()).hexdigest()[:20]
        records.append({"catalog_schema_version":1,"source_registry_schema_version":1,"run_id":expected_run,"plugin_slug":expected_slug,"plugin_version":expected_version,"namespace":namespace(route),"route":route,"endpoint_identity":identity,"methods":resolved,"method_origin":"runtime_registry" if resolved else "unresolved","callback":callback,"callback_type":raw.get("callback_type") or kind(callback),"callback_file":raw.get("source_file"),"callback_line":raw.get("source_line"),"permission_callback":raw.get("permission_callback"),"permission_callback_type":raw.get("permission_callback_type") or kind(raw.get("permission_callback")),"permission_callback_file":raw.get("permission_source_file"),"permission_callback_line":raw.get("permission_source_line"),"authentication":"public" if raw.get("permission_callback")=="__return_true" else "unresolved","authentication_evidence":["permission_callback___return_true"] if raw.get("permission_callback")=="__return_true" else ["permission_behavior_not_observed"],"schema_parameters":params,"runtime_parameters":[],"parameter_origins":[p["parameter_origin"] for p in params],"ownership":classification,"ownership_evidence":evidence,"limitations":sorted(limits)})
    keyed={json.dumps(row,sort_keys=True,separators=(",",":")):row for row in records}; records=sorted(keyed.values(),key=lambda r:json.dumps(r,sort_keys=True))
    plugin=[r for r in records if r.get("ownership")=="plugin"]; counts=Counter(m for r in plugin for m in r.get("methods",[]))
    ownership=Counter(r.get("ownership") for r in records); auth=Counter(r.get("authentication") for r in plugin)
    return {"catalog_schema_version":1,"catalog_run_id":expected_run,"registry_artifact":{"path":None,"sha256":None,"captured_at":registry.get("captured_at"),"schema_version":registry.get("schema_version")},"plugin":{"slug":expected_slug,"version":expected_version},"records":records,"metrics":{"route_path_count":len({r.get("route") for r in registry["routes"] if isinstance(r,dict)}),"raw_endpoint_count":len(registry["routes"]),"normalized_endpoint_count":len(records),"deduplicated_endpoint_count":len(registry["routes"])-len(records),"plugin_owned_endpoint_count":len(plugin),"wordpress_core_endpoint_count":ownership["wordpress_core"],"dependency_endpoint_count":ownership["dependency"],"unrelated_plugin_endpoint_count":ownership["unrelated_plugin"],"unresolved_ownership_count":ownership["unresolved"],"methods":dict(sorted(counts.items())),"authentication":dict(sorted(auth.items())),"schema_parameter_count":sum(len(r.get("schema_parameters",[])) for r in plugin),"runtime_only_parameter_count":0,"unsupported_args_value_count":sum(len(p["unsupported_value_markers"]) for r in plugin for p in r["schema_parameters"]),"unresolved_callback_count":sum(r["callback_type"]=="unresolved" for r in records),"unresolved_permission_callback_count":sum(r["permission_callback_type"]=="unresolved" for r in records),"limited_endpoint_count":sum(bool(r["limitations"]) for r in records)}}
def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("registry",type=Path); p.add_argument("output",type=Path); p.add_argument("--run-id",required=True); p.add_argument("--slug",required=True); p.add_argument("--version",required=True); a=p.parse_args()
    catalog=normalize(read(a.registry),a.run_id,a.slug,a.version); digest=hashlib.sha256(a.registry.read_bytes()).hexdigest(); catalog["registry_artifact"]["path"]=str(a.registry); catalog["registry_artifact"]["sha256"]=digest
    for record in catalog["records"]: record["source_registry_sha256"]=digest
    a.output.parent.mkdir(parents=True,exist_ok=True); tmp=a.output.with_suffix(".tmp"); tmp.write_text(json.dumps(catalog,indent=2,sort_keys=True)+"\n"); tmp.replace(a.output); return 0
if __name__=="__main__": raise SystemExit(main())
