# Benchmark run summary - coefficient sweep

Generated from `phuzz-main/code/fuzzer/output/benchmarks/**/benchmark_results.json` on 2026-05-17.

Scope used for the coefficient sweep: 6 coefficients, 5 plugins per coefficient, 30 PHUZZ-vs-HOOK comparisons, 60 mode runs.

## Reading guide

- `PHUZZ` is `PHUZZ_SCORING_MODE=1`; `HOOK` is `PHUZZ_SCORING_MODE=2`.
- Every summarized result reports `time_budget_seconds=600`, so each mode was run for 10 minutes.
- `first s / req` means time and request count to first deduplicated vulnerability.
- `--` means no unique vulnerability was found in that mode-run.
- The JSON artifacts prove the metrics. The coefficient labels come from run-session verification logs and the user-provided mapping for the added 2026-05-15 runs.

## Coefficient Mapping

| coefficient | plugins covered | HOOK ahead | PHUZZ ahead | no-vuln ties | time ties | evidence |
|---:|---:|---:|---:|---:|---:|---|
| 0.8 | 5 | 1 | 0 | 2 | 2 | user-provided mapping, artifact roots present |
| 0.6 | 5 | 2 | 0 | 2 | 1 | confirmed by session log; split artifact roots merged here |
| 0.4 | 5 | 2 | 1 | 2 | 0 | confirmed by session log |
| 0.2 | 5 | 1 | 2 | 2 | 0 | user-provided mapping, artifact roots present |
| 0.05 | 5 | 2 | 1 | 2 | 0 | confirmed by session log |
| 0.01 | 5 | 0 | 3 | 2 | 0 | confirmed by session log |

Across the coefficient sweep: HOOK is ahead in 8 comparisons, PHUZZ is ahead in 7 comparisons, 12 comparisons found no unique vulnerability in either mode, and 3 comparisons tied on first-vulnerability time.

Interpretation: hook-aware mode is visibly affecting benchmark behavior, but this sweep is not a clean dominance result. The strongest HOOK-leaning settings in these single runs are `0.6`, `0.4`, and `0.05`; the `0.01` run leans PHUZZ on all targets that produced a vulnerability.

## Detailed Comparisons

### Coefficient 0.8

| plugin | HOOK vuln | PHUZZ vuln | HOOK first s / req | PHUZZ first s / req | result |
|---|---:|---:|---:|---:|---|
| crm-perks-forms | 3 | 3 | 6 / 3 | 6 / 36 | tie time |
| photo-gallery | 1 | 1 | 69 / 93 | 131 / 173 | HOOK faster |
| seo-local-rank | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| totop-link | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| webp-converter-for-media | 1 | 1 | 5 / 4 | 5 / 3 | tie time |

### Coefficient 0.6

| plugin | HOOK vuln | PHUZZ vuln | HOOK first s / req | PHUZZ first s / req | result |
|---|---:|---:|---:|---:|---|
| crm-perks-forms | 3 | 3 | 0 / 33 | 4 / 36 | HOOK faster |
| photo-gallery | 1 | 1 | 5 / 11 | 58 / 126 | HOOK faster |
| seo-local-rank | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| totop-link | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| webp-converter-for-media | 1 | 1 | 2 / 2 | 2 / 2 | tie time |

### Coefficient 0.4

| plugin | HOOK vuln | PHUZZ vuln | HOOK first s / req | PHUZZ first s / req | result |
|---|---:|---:|---:|---:|---|
| crm-perks-forms | 3 | 3 | 3 / 23 | 6 / 40 | HOOK faster |
| photo-gallery | 1 | 1 | 22 / 62 | 72 / 133 | HOOK faster |
| seo-local-rank | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| totop-link | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| webp-converter-for-media | 1 | 1 | 4 / 2 | 3 / 3 | PHUZZ faster |

### Coefficient 0.2

| plugin | HOOK vuln | PHUZZ vuln | HOOK first s / req | PHUZZ first s / req | result |
|---|---:|---:|---:|---:|---|
| crm-perks-forms | 3 | 3 | 7 / 145 | 4 / 47 | PHUZZ faster |
| photo-gallery | 1 | 1 | 53 / 73 | 10 / 14 | PHUZZ faster |
| seo-local-rank | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| totop-link | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| webp-converter-for-media | 1 | 1 | 3 / 2 | 5 / 3 | HOOK faster |

### Coefficient 0.05

| plugin | HOOK vuln | PHUZZ vuln | HOOK first s / req | PHUZZ first s / req | result |
|---|---:|---:|---:|---:|---|
| crm-perks-forms | 3 | 3 | 2 / 12 | 4 / 36 | HOOK faster |
| photo-gallery | 1 | 1 | 214 / 277 | 17 / 55 | PHUZZ faster |
| seo-local-rank | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| totop-link | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| webp-converter-for-media | 1 | 1 | 3 / 2 | 5 / 2 | HOOK faster |

### Coefficient 0.01

| plugin | HOOK vuln | PHUZZ vuln | HOOK first s / req | PHUZZ first s / req | result |
|---|---:|---:|---:|---:|---|
| crm-perks-forms | 3 | 3 | 6 / 210 | 3 / 71 | PHUZZ faster |
| photo-gallery | 1 | 1 | 25 / 62 | 18 / 47 | PHUZZ faster |
| seo-local-rank | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| totop-link | 0 | 0 | -- / -- | -- / -- | no-vuln tie |
| webp-converter-for-media | 1 | 1 | 3 / 3 | 2 / 4 | PHUZZ faster |

## Plugin-Level Pattern

| plugin | comparisons | HOOK ahead | PHUZZ ahead | no-vuln ties | time ties | observation |
|---|---:|---:|---:|---:|---:|---|
| crm-perks-forms | 6 | 3 | 2 | 0 | 1 | mixed, slightly HOOK-leaning |
| photo-gallery | 6 | 3 | 3 | 0 | 0 | mixed |
| seo-local-rank | 6 | 0 | 0 | 6 | 0 | no unique vuln in either mode |
| totop-link | 6 | 0 | 0 | 6 | 0 | no unique vuln in either mode |
| webp-converter-for-media | 6 | 2 | 2 | 0 | 2 | mixed / near-tie |

## Report-Ready Takeaways

1. The coefficient sweep covers six hook-energy base weights: `0.8`, `0.6`, `0.4`, `0.2`, `0.05`, and `0.01`.
2. `0.6`, `0.4`, and `0.05` are the most favorable single-run settings for HOOK in this dataset.
3. `0.01` is unfavorable for HOOK in this dataset: every target that produced a unique vulnerability was faster in PHUZZ mode.
4. `0.2` is mixed but leans PHUZZ on `crm-perks-forms` and `photo-gallery`.
5. `seo-local-rank` and `totop-link` are negative-result targets across all coefficients because neither mode found a unique vulnerability.
6. Suggested wording: hook-aware scoring can reduce time-to-first unique vulnerability for selected coefficients and plugins, but the current single-run 10-minute sweep does not prove universal superiority over baseline PHUZZ.

## Artifact Roots

The report groups results by coefficient. These roots are listed only for traceability:

- `0.8`: `20260515-090240-*`
- `0.6`: `20260516-081248-*` plus `20260516-115420-*`
- `0.4`: `20260515-222906-*`
- `0.2`: `20260515-150452-*`
- `0.05`: `20260516-134915-*`
- `0.01`: `20260516-193919-*`

Older pre-sweep runs are still present under `20260513-*`, but they are excluded from the coefficient sweep because they are not part of the `0.8 / 0.6 / 0.4 / 0.2 / 0.05 / 0.01` comparison set.
