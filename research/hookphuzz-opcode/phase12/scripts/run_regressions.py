#!/usr/bin/env python3
from __future__ import annotations
import datetime as dt, subprocess, sys
from pathlib import Path

root=Path(__file__).resolve().parents[4]; results=root/'research/hookphuzz-opcode/phase12/results'; logs=results/'regression-logs'; logs.mkdir(exist_ok=True)
commands=[('phase9',['bash','research/hookphuzz-opcode/phase9/run.sh']),('phase10',['bash','research/hookphuzz-opcode/phase10/run.sh']),('phase11',['bash','research/hookphuzz-opcode/phase11-rest-method-generalization/run.sh'])]
rows=[]
for name, command in commands:
    start=dt.datetime.now(dt.timezone.utc); out=(logs/f'{name}.stdout.log').open('w'); err=(logs/f'{name}.stderr.log').open('w')
    try: code=subprocess.run(command,cwd=root,stdout=out,stderr=err,timeout=180).returncode
    except subprocess.TimeoutExpired: code=124
    finally: out.close(); err.close()
    end=dt.datetime.now(dt.timezone.utc); rows.append((name,command,start,end,code))
report=['# Final Phase 12 regressions','']
for name, command, start, end, code in rows:
    report += [f'## {name}', '', f'- command: `{" ".join(command)}`', f'- start: {start.isoformat()}', f'- end: {end.isoformat()}', f'- exit code: {code}', f'- stdout: `results/regression-logs/{name}.stdout.log`', f'- stderr: `results/regression-logs/{name}.stderr.log`', f'- result: {"PASS" if code == 0 else "FAIL"}', '']
(results/'regression-results-final.md').write_text('\n'.join(report),encoding='utf-8')
raise SystemExit(0 if all(row[-1] == 0 for row in rows) else 1)
