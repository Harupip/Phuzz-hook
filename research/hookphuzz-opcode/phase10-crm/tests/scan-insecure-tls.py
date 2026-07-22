#!/usr/bin/env python3
import sys
from pathlib import Path
root=Path(sys.argv[1]); forbidden=('--insecure','curl -k','no-check-certificate','GIT_SSL_NO_VERIFY','NODE_TLS_REJECT_UNAUTHORIZED','verify=False','sslverify=false')
hits=[]
for path in root.rglob('*'):
    if not path.is_file() or path.name in {'README.md','scan-insecure-tls.py'} or 'results' in path.parts: continue
    try: text=path.read_text(encoding='utf-8')
    except UnicodeDecodeError: continue
    for n,line in enumerate(text.splitlines(),1):
        if any(token in line for token in forbidden): hits.append(f'{path.relative_to(root)}:{n}:{line}')
print('\n'.join(hits) if hits else 'INSECURE_TLS_SCAN_PASS')
raise SystemExit(1 if hits else 0)
