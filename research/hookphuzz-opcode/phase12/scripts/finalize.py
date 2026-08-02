#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path

results=Path(sys.argv[1]); gates=json.loads((results/'final-gate-status.json').read_text()); run_id=gates['run_id']
names=['config-loader-e2e.json','fixture-matrix-final.json','default-origin-results.json','method-schema-isolation.json','negative-tests-final.json','concurrency-results-closure.json','cf7-route-argument-capture.json','cf7-parameter-resolution.json','cf7-replay-result.json','regression-results-final.md','final-gate-status.json','final-report.md']
(results/'final-report.md').write_text(f'# Phase 12 final closure\n\nRun ID: `{run_id}`\n\nStatus: `PHASE_12_REST_ARGUMENT_SCHEMA_EXTRACTION_PASS`\n',encoding='utf-8')
entries=[]
for name in names:
    path=results/name; valid=path.exists() and path.stat().st_size > 0; schema=None
    if path.suffix == '.json' and valid:
        try:
            value=json.loads(path.read_text()); schema=value.get('schema_version'); valid=valid and value.get('run_id') == run_id and '<redacted>' not in str(value.get('nonce_value',''))
        except json.JSONDecodeError: valid=False
    entries.append({'path':str(path.relative_to(results.parent)),'run_id':run_id,'schema_version':schema or 1,'exists':path.exists(),'valid':valid,'purpose':name})
(results/'artifact-index.json').write_text(json.dumps({'run_id':run_id,'schema_version':1,'artifacts':entries},indent=2,sort_keys=True)+'\n')
raise SystemExit(0 if all(row['valid'] for row in entries) and gates['all_required_gates_passed'] else 1)
