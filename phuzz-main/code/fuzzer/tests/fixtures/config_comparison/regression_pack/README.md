# Config comparison regression pack

This is a synthetic set of raw PHUZZ configs. Use `baseline.json` as the expected config and compare each file in `cases/` as the actual config. The manifest records the policy and expected status for every case.

From `phuzz-main/code/fuzzer`, for example:

```powershell
rtk proxy python -m config_comparison.cli --expected tests/fixtures/config_comparison/regression_pack/baseline.json --actual tests/fixtures/config_comparison/regression_pack/cases/04-target-mismatch.json --policy strict
```

Use the policy listed for the case in `manifest.json`. `03-semantic-transient-metadata.json` is the only case using `semantic`; `14-nontransient-metadata-mismatch.json` shows that semantic mode still compares nontransient metadata. `17-missing-cookie.json` is a short case where the actual config omits cookies from the baseline.

The configs are comparator fixtures only. They are not plugin evidence, runtime seeds, or vulnerability claims. `NO_REFERENCE` and `AMBIGUOUS` require bulk reference-index inputs and are outside this direct-pair pack.
