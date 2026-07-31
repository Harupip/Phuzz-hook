# Phase 10 CRM Perks Forms

## Goal

Prove authenticated AJAX discovery, nested parameter generation, and semantic
replay against CRM Perks Forms 1.0.7.

## Run

```bash
bash research/hookphuzz-opcode/phase10-crm/run.sh
```

Use `HOOKPHUZZ_BUILD_CA_FILE` only for an approved private TLS root.

## Evidence

The retained result is `PHASE_10_CRM_PASS`. Verify current work with
`results/gate-summary.json`, `final-status.txt`, and replay evidence.

## Boundary

The lab reuses frozen Phase 9 extension source. UOPZ observes registration,
callback entry, and `cfx_form::post`; it does not modify CRM source. Secrets
remain transient and reports stay redacted.
