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

## One-command comparison using `phuzz.env`

Set `CONFIG_COMPARE_EXPECTED` and `CONFIG_COMPARE_ACTUAL` in
`phuzz-main/code/phuzz.env`. Paths may be absolute or relative to
`phuzz-main/code`. `CONFIG_COMPARE_POLICY` accepts `strict` or `semantic` and
defaults to `strict`.

From `phuzz-main/code`, run:

```powershell
rtk proxy pwsh -NoProfile -File .\compare-configs.ps1
```

The script calls the offline comparator and returns its exit code: 0 for
`MATCH`, 1 for `MISMATCH`, and 2 for `INVALID` or an input error. It does not
start online-linked or Docker.

## Offline comparison of one online-linked final config

`phuzz.env` controls the optional prompt at the end of a successful online-linked
run: `ONLINE_COMPARE_PROMPT=1` enables it, `0` disables it (missing key defaults
to disabled). The checked-in env enables it. In an interactive terminal with
exported final configs, answer `y`, select a numbered final config from that run,
then enter the experiment reference JSON path. Relative paths are resolved from
`phuzz-main/code`; absolute paths are also accepted. Enter cancels at each step.
Redirected/non-interactive input skips the prompt. Comparison results and errors
are reported separately and do not change the discovery exit status.

After `online-linked` finishes and exports `final-configs`, inspect that
directory and choose exactly one final JSON plus exactly one experiment
reference JSON. From `phuzz-main/code`, run:

```text
rtk proxy python -m fuzzer.config_comparison.online_linked --compare-final-config "PATH_TO_SELECTED_FINAL_CONFIG" --compare-with "PATH_TO_EXPERIMENT_REFERENCE"
```

The command does not rerun discovery, prompt for a path, start Docker, or
select another final config. It compares with the existing semantic
comparator and the fixed entrypoint policy `ignored_metadata_paths={"/metadata"}`:
the complete top-level metadata subtree is ignored, including unknown nested
fields. A request parameter actually named `metadata`, authentication values,
and selectors remain part of the comparison.

For a valid run, the report is written to the run directory as
`config-comparison.json`. The batch state's other discovery, candidate, and
vulnerability fields are retained; only `config_comparison` is added or
replaced with the latest summary. Exit code 0 means `MATCH`, 1 means a
comparator `MISMATCH`, and 2 means `INVALID`, an input/path error, or an I/O
error. The report records absolute resolved expected/reference and
actual/selected-final paths and all status counts.

The existing `config_comparison.cli --policy semantic` contract is unchanged:
it still ignores only the semantic paths listed in `policy.py`, not every
metadata field. Whole-`/metadata` ignoring is specific to the offline
online-linked entrypoint.

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
