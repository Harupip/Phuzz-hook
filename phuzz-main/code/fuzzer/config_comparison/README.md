# PHUZZ config comparison V1

This module compares raw PHUZZ configuration declarations with a user-prepared
reference. It is deliberately independent of the generator, loader, resolver,
fuzzer runtime, Docker, and network execution.

## Input schema

Each input is one raw PHUZZ config object:

```json
{
  "target": "http://web/wp-admin/admin-ajax.php",
  "methods": ["POST"],
  "body_params": {
    "data": [{"name": "action", "value": "demo"}],
    "fixed": ["action"],
    "fuzz": [],
    "weight": 1
  }
}
```

The supported sections are `headers`, `cookies`, `query_params`, and
`body_params`. `fixed` and `fuzz` are preserved as regex declarations. V1 does
not recreate PHUZZ effective fixed-wins/default-fuzz resolution, seed replay,
HAR/login handling, or request execution. `value` and `seeds` are separate
declarations; a scalar value is not equivalent to a singleton seed list.

Values use typed comparison: booleans, integers, strings, null, dictionaries,
and lists retain their types. Dictionary order is ignored; list order is kept,
except that the alternatives in one `seeds` declaration are a set. Header
names are not folded for HTTP case-insensitivity because the existing resolver
and Content-Type branch are spelling-sensitive. Query parameters embedded in
the target are retained as query declarations, including blank values.

## Policies and identity

`strict` is the default and checks request declarations plus all metadata and
other fields. `semantic` ignores only the exact transient paths listed in
`policy.py`; it still checks auth fields, `weight`, `login`, unknown metadata,
values, sources, and selectors. Extra actual parameters can be allowed with a
source/name pair, for example `body_params:nonce`; broad selectors are never
silently allowed. `effective` is reserved and explicitly unsupported in V1.

Bulk comparison indexes exact request identity: family, normalized method set,
endpoint, and AJAX/admin-post action. A missing reference is `NO_REFERENCE`,
multiple references are `AMBIGUOUS`, and invalid reference sets fail closed.
Filenames, plugin metadata, and auth metadata do not disambiguate references.

## CLI

From `phuzz-main/code/fuzzer`:

```text
python -m config_comparison.cli --expected FILE_OR_DIR --actual FILE_OR_DIR \
  [--policy strict|semantic] [--allow-extra body_params:nonce] \
  [--format json|text] [--output REPORT]
```

The CLI reads UTF-8 and UTF-8-sig JSON, detects duplicate object keys, and
recurses only through JSON files in an input folder. It never reads a runtime
`generated_config_summary.json` as a config. JSON output contains policy,
counts for all five statuses, results, reference errors, and input errors.
Exit codes are 0 for all matches, 1 for mismatch/no-reference/ambiguity, and 2
for invalid configs, invalid references, input errors, or invalid arguments.

Add a new reference by placing a separately curated raw JSON fixture in the
reference corpus and recording its provenance; do not modify the experiment
source or use a generated actual snapshot as the expected oracle.

## Evidence labels

Unit tests prove normalization, comparison, identity, indexing, and CLI
contracts. Fixture tests prove copied legacy semantics. The opt-in CF7 plugin
smoke reads the pinned ZIP and source lines offline; it is source-backed
fixture evidence, not runtime callback or vulnerability proof. The exporter
test is an `exporter integration` check using an independently prepared seed;
it is not automatic discovery proof. No V1 test runs Docker, fuzzing, HTTP,
or the PHUZZ runtime.
