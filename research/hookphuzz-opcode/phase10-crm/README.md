# Phase 10A CRM Perks Forms

Independent CRM-only lab. Reuses Phase 9 extension source unchanged at Docker build time. WordPress MU observer uses UOPZ only for AJAX registration, callback entry, and `cfx_form::post` root-read evidence; CRM source stays read-only.

Run clean:

```bash
bash research/hookphuzz-opcode/phase10-crm/run.sh
```

`results/` is deleted at start. OPcache/JIT disabled. Cookie and nonce remain `/tmp` inside the transient web container; reports contain redacted references only.

If this network uses an approved private TLS root, export it locally then pass its PEM file without committing it:

```bash
HOOKPHUZZ_BUILD_CA_FILE=/secure/path/environment-root-ca.crt bash research/hookphuzz-opcode/phase10-crm/run.sh
```

The runner validates the PEM and mounts it only as a BuildKit secret. Public networks need no variable.
