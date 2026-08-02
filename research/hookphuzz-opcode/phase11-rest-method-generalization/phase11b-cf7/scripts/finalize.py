#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


RESULTS = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path('/results')


def load(name: str, default: dict) -> dict:
    try:
        return json.loads((RESULTS / name).read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return default


proof = load('phase11b-status.json', {})
regression = load('regression-summary.json', {})
checks = regression.get('checks', {}) if isinstance(regression, dict) else {}
all_regressions = bool(checks) and all(value == 'PASS' for value in checks.values())
passed = bool(proof.get('gates')) and all(proof.get('gates', {}).values()) and proof.get('negative_tests_passed') is True and all_regressions
status = 'PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_PASS' if passed else 'PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_FAIL'
proof['status'] = status
proof['regressions_passed'] = all_regressions
(RESULTS / 'phase11b-status.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n', encoding='utf-8')
lines = [
    '# Phase 11B CF7 authenticated REST proof', '', '## Status', '', f'`{status}`', '',
    '## Regression', '',
    *[f'- {name}: {value}' for name, value in checks.items()], '',
    '## Evidence', '',
    '- `cf7-route-registration.json`, `method-resolution.json`, `route-materialization.json`, `generated-config.json`, `request-preparation.json`, `callback-proof.json`, `parameter-proof.json`, `request-correlation.json`, and `negative-tests.json` are current-run artifacts.',
]
(RESULTS / 'final-report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
raise SystemExit(0 if passed else 1)
