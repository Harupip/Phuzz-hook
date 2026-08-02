# Phase 11B CF7 authenticated REST proof

Runs only the pinned local Contact Form 7 5.7.7 archive in a disposable local
Docker WordPress 6.5.5 environment. It creates disposable users, performs a
real local form login, obtains a fresh core REST nonce, and replays the
production-exported GET config.

```bash
bash research/hookphuzz-opcode/phase11-rest-method-generalization/phase11b-cf7/run.sh
```

Cookies and nonces stay in memory and are redacted from all persisted files.
