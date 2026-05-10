from __future__ import annotations

from pathlib import Path


def detect_stale_seed_artifacts(
    *,
    report_direct_candidates: int,
    source_pipeline: Path,
    source_plugin: Path,
) -> list[str]:
    warnings: list[str] = []
    pipeline_text = source_pipeline.read_text(encoding="utf-8") if source_pipeline.exists() else ""
    plugin_text = source_plugin.read_text(encoding="utf-8") if source_plugin.exists() else ""

    has_mapping_rules = "/wp-admin/admin-ajax.php" in pipeline_text and "/wp-admin/admin-post.php" in pipeline_text
    has_direct_seed_hooks = any(
        token in plugin_text
        for token in (
            "wp_ajax_",
            "wp_ajax_nopriv_",
            "admin_post_",
            "admin_post_nopriv_",
        )
    )

    if has_mapping_rules and has_direct_seed_hooks and int(report_direct_candidates) == 0:
        warnings.append(
            "Source artifacts appear stale: source code contains direct HTTP seed hooks, but hook_gap_report.json reports zero direct HTTP seed candidates."
        )

    return warnings
