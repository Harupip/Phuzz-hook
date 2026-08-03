#!/usr/bin/env python3
from __future__ import annotations
import json,sys
from pathlib import Path
catalogs=[json.loads(Path(p).read_text()) for p in sys.argv[1:-1]]; rows=[r for c in catalogs for r in c['records']]
def pick(pred): return next((r for r in rows if pred(r)),None)
public=pick(lambda r:r['ownership']=='plugin' and r['authentication']=='public' and r['methods'] and r['callback_type']!='unresolved')
schema=pick(lambda r:r['ownership']=='plugin' and r['schema_parameters'] and r['methods'])
auth=pick(lambda r:r['ownership']=='plugin' and r['authentication']=='authenticated' and r['methods'])
out={'public':{'record':public,'reason':'supported_catalog_evidence' if public else 'no_supported_public_endpoint'},'authenticated':{'record':auth,'reason':'supported_catalog_evidence' if auth else 'authentication_not_observed_in_phase13_catalog'},'schema_parameter':{'record':schema,'reason':'registered_args_present' if schema else 'no_plugin_owned_schema_parameter'},'future_runtime_only':{'plugin':'contact-form-7','parameter':'search','phase13_schema_evidence':'absent','phase13_runtime_evidence':'not_yet_produced','phase12_regression_baseline':'runtime-only'}}
Path(sys.argv[-1]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
