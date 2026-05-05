# PHUZZ Hook-Score Visualization Design

**Goal:** Build a practical visualization surface for `phuzz-main` that makes it obvious when hook-aware feedback is affecting scheduling, and whether that hook-aware behavior is better than the original PHUZZ energy path.

## Scope

The design covers two related outputs built on one shared data model:

- an **after-run report** for inspecting one run or comparing two runs
- a future **live dashboard** for watching one run while it is still executing

The first implementation target is the after-run report. The live dashboard is explicitly phase 2 and must reuse the same normalized model instead of introducing a separate parsing path.

## Primary questions the visualization must answer

The system should let a reader answer these questions quickly:

1. Is hook-aware feedback actually changing PHUZZ decisions inside a run?
2. Which requests and callbacks caused those changes?
3. Is the hook signal rewarding rare callback exploration or just amplifying repeated traffic?
4. Do hook-aware boosts correlate with better outcomes such as more useful errors, exceptions, or vulnerabilities?
5. Compared with a baseline PHUZZ run, is the hook-aware run worth keeping and tuning further?

## User-facing design

### Reading flow

The after-run report should lead with the clearest evidence first:

1. **Run overview**
2. **One concrete boosted candidate**
3. **Decision timeline**
4. **Callback scoreboard**
5. **Cross-run comparison**, when a baseline run is also provided

This order is intentional. The reader should first see that the run changed, then see one specific changed case, and only after that scan the broader trend and callback-level context.

### Run overview

The overview should show compact KPIs:

- boosted decisions count and percentage
- average and maximum `hook_energy`
- average and maximum `priority_delta`
- average and maximum `energy_delta`
- coverage ratio
- callbacks registered / executed / still blind
- exceptions count
- vulnerability counts

If the report is built from two runs, the overview should show baseline and hook-aware values side by side with deltas.

### Concrete boosted candidate

The report should immediately surface one representative candidate that demonstrates visible hook impact. The card should show:

- `coverage_id`
- mutated parameter name and parameter type
- `base_score` and `score`
- `base_priority` and `priority`
- `base_energy` and `final_energy`
- `hook_request_id`
- `hook_energy` and `hook_energy_avg`
- outcome tags such as `exception`, `error`, or vulnerability class

If the linked request artifact is available, the drilldown should also show the executed callbacks that explain the hook score.

### Decision timeline

The timeline should tell the scheduling story across the run. Each row should show:

- request or candidate identity
- `base_priority -> priority`
- `base_energy -> final_energy`
- `hook_energy`
- endpoint and method when available
- a short interpretation tag such as `strong boost`, `small boost`, or `repeated-signal decay`

The timeline exists to prove that hook-aware feedback is not theoretical metadata; it altered ordering pressure inside the run.

### Callback scoreboard

The callback view should make rarity and blindspots legible:

- top rare callbacks still carrying strong value
- top frequent callbacks whose score should now be decaying
- registered callbacks never executed yet
- optionally, callbacks newly reached only in the hook-aware run

This is the main view for tuning the rarity formula and hook weighting.

### Cross-run comparison

If the report receives both a baseline run and a hook-aware run, it should unlock comparison sections that show:

- summary metric deltas
- new callbacks reached in the hook-aware run
- changes in outcome counts
- top mutated parameters by outcome change
- interpretation flags such as:
  - `hook improved rare callback exploration`
  - `hook increased boosts without outcome gains`
  - `hook mostly amplified repeated ajax traffic`

Cross-run comparison is the primary decision surface for whether hook-aware energy is better than the original PHUZZ path.

## Architecture

The implementation should be split into three layers.

### 1. Artifact readers

These readers ingest raw files such as:

- `hook-energy-decisions.jsonl`
- `exceptions-and-errors.json`
- `vulnerable-candidates.json`
- request artifacts under the hook coverage request directory
- coverage summary snapshots such as `total_coverage.json`
- optional convenience summaries such as `HOOK_ENERGY_RUN_METRICS.json`

Readers should stay close to the source formats and avoid embedding presentation logic.

### 2. Normalized run model

Readers feed one shared internal model that becomes the single source of truth for both report generation and the future live dashboard.

This layer should compute and store:

- run metadata
- run summary metrics
- decision records
- callback records
- request records
- optional cross-run comparison records

### 3. Presenters

Presenters consume only the normalized model:

- `report.html`
- `report.json`
- `report-summary.md`
- phase 2 live dashboard renderer

This separation keeps parsing and presentation independent and reduces the risk of having separate logic for after-run and live views.

## Input modes

### Single-run mode

This mode supports within-run analysis. It accepts one run directory or one run descriptor with pointers to:

- decision trace
- candidate outcome files
- request artifacts
- hook coverage summary

This mode must still be useful even when some optional artifacts are missing.

### Run-pair mode

This mode supports baseline-versus-hook-aware comparison. It accepts:

- one baseline PHUZZ run
- one hook-aware run

Both runs must normalize into the same schema so the comparison layer can remain generic.

## Normalized data contract

The normalized report model should contain the following top-level objects.

### `run_metadata`

Fields should include:

- run label
- target plugin and target endpoint family when known
- run timestamp or time window
- mode: `baseline` or `hook-aware`
- config hints such as hook weights when available

### `run_summary`

Fields should include:

- requests total
- registered callbacks total
- executed callbacks total
- blindspots total
- coverage ratio
- exceptions count
- vulnerability counts by class
- boosted decisions count
- average and maximum `hook_energy`
- average and maximum `priority_delta`
- average and maximum `energy_delta`

### `decision_records[]`

Each record should include:

- `coverage_id`
- `hook_request_id`
- mutated parameter name and type
- `base_score`
- `score`
- `base_priority`
- `priority`
- `base_energy`
- `final_energy`
- `hook_energy`
- `hook_energy_avg`
- endpoint or target identity when available
- outcome tags

### `callback_records[]`

Each record should include:

- callback id
- hook name
- callback identity
- executed count
- request count
- current rarity-related score
- next score if executed again
- status: executed, registered-only, or blindspot

### `request_records[]`

Each record should include:

- request id
- endpoint
- request method
- linked `coverage_id` if correlation succeeds
- request time if available
- executed callbacks list
- derived rarity contribution summary

### `comparison`

When two runs are provided, the comparison object should include:

- baseline label
- hook-aware label
- summary metric deltas
- callbacks newly reached in the hook-aware run
- callbacks lost relative to baseline
- outcome deltas
- top interpretation flags

## Output artifacts

The generator should emit three deliverables.

### `report.html`

The main human-readable artifact. It should be self-contained enough to open locally without extra services.

### `report.json`

The machine-readable normalized model. This file is the debug and regression-testing anchor and should be stable enough for snapshot tests.

### `report-summary.md`

A short textual summary suitable for evidence logs, commit context, or thesis notes.

## Comparison strategy

The visualization must support both comparison layers, but not confuse them.

### Within-run comparison

This layer proves hook-aware scheduling was active inside the run. It is based on values such as:

- `base_priority` versus `priority`
- `base_energy` versus `final_energy`
- `hook_energy`

### Cross-run comparison

This layer judges whether the hook-aware system was useful overall. It compares baseline and hook-aware runs on:

- coverage ratio
- callback reach
- blindspots
- exceptions
- vulnerabilities
- outcome-bearing boosted candidates

Within-run comparison explains mechanism. Cross-run comparison judges value.

## Failure handling

The generator should fail soft whenever possible.

### Missing decision trace

If `hook-energy-decisions.jsonl` is absent, the report should still render summary and outcome sections, while marking the timeline as unavailable.

### Missing request artifacts

If request logs are absent, the report should still show candidate-level hook boosts but disable callback drilldown.

### Inconsistent request callback payloads

Live artifacts may encode executed callbacks inconsistently. The parser should normalize the known shapes when possible and emit a warning section when some records cannot be interpreted safely.

### Uneven baseline and hook-aware runs

If the two runs are not comparable in scope or volume, the report should still show them side by side but add a visible caution that the comparison may be biased.

The report must not collapse entirely because one optional source file is missing.

## Testing strategy

### Parser tests

Unit tests should cover the supported raw file shapes for:

- decision traces
- candidate outcome files
- request artifacts
- coverage summary snapshots

### Normalization tests

Tests should verify:

- computed `priority_delta`
- computed `energy_delta`
- boosted decision counts
- callback status classification
- cross-run delta calculations

### Snapshot tests

The normalized `report.json` should be snapshot-tested for one or more fixed fixtures. This gives stable regression coverage without depending on HTML rendering details.

### HTML smoke tests

The HTML generator should have lightweight checks that confirm required sections render when their source data exists.

## Tuning guidance encoded in the report

The report should help the reader choose the next tuning move.

- If boosts increase but useful outcomes do not, hook weights may be too high.
- If repeated callbacks dominate, the rarity formula may not decay fast enough.
- If blindspots remain unchanged, mutation strategy or seeds may be the limiting factor rather than scoring.
- If rare callback reach improves alongside useful outcomes, the hook-aware path is behaving as intended.

These interpretations belong in the report because the tool is meant for tuning, not just passive visualization.

## Phasing

### Phase 1

Build:

- artifact readers
- normalized `report.json`
- after-run `report.html`
- `report-summary.md`
- single-run and run-pair support

### Phase 2

Build:

- live dashboard renderer backed by the same normalized model
- incremental updates from active run artifacts

No separate live-only parsing path should be introduced.

## Risks and mitigations

- Existing run artifacts may not be perfectly synchronized in wall-clock time; the report should preserve source timestamps and surface mismatches.
- Local browser-based mockup review was unstable in this environment; the production after-run report should be file-openable without depending on a fragile transient server.
- The workspace already contains unrelated local modifications, so implementation should keep the visualization work narrowly scoped and avoid touching existing fuzzing behavior unless later plan steps explicitly call for it.
