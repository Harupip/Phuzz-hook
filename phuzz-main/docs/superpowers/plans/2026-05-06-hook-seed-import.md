# Hook Seed Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone seed importer under `code/fuzzer/hook_energy/seed_generation` that reads external handoff artifacts, writes normalized replayable seed files, and sends non-replayable callbacks to a manual-analysis queue.

**Architecture:** Keep the importer separate from the existing hook-energy runtime. Use one small package for seed-generation models, import orchestration, and stale-artifact checks. Write JSON artifacts into `code/fuzzer/output/seed_generation/` so later PHUZZ integration can consume them without coupling import logic to the fuzzer runtime.

**Tech Stack:** Python 3, standard library (`json`, `pathlib`, `dataclasses`, `tempfile`, `unittest`), existing `hook_energy` package layout

---

## File Structure

### New files

- `code/fuzzer/hook_energy/seed_generation/__init__.py`
  - Package exports for the seed importer.
- `code/fuzzer/hook_energy/seed_generation/models.py`
  - Dataclasses for normalized replayable requests, manual backlog entries, and import summary payloads.
- `code/fuzzer/hook_energy/seed_generation/stale_check.py`
  - Source-code verification helpers that detect stale handoff artifacts without synthesizing requests.
- `code/fuzzer/hook_energy/seed_generation/importer.py`
  - Main import pipeline: read handoff JSON, filter replayable seeds, split auth queues, collect backlog, write artifacts.
- `code/fuzzer/tests/test_seed_generation_importer.py`
  - TDD coverage for filtering, metadata preservation, manual queue handling, stale warnings, and file output.

### Modified files

- `code/fuzzer/hook_energy/__init__.py`
  - Export the new importer entry point if package-level access is useful for later integration.

### Generated output paths

- `code/fuzzer/output/seed_generation/imported_unauth_seeds.json`
- `code/fuzzer/output/seed_generation/imported_auth_seeds.json`
- `code/fuzzer/output/seed_generation/manual_analysis_queue.json`
- `code/fuzzer/output/seed_generation/import_summary.json`

## Task 1: Build Replayable Import Core

**Files:**
- Create: `code/fuzzer/tests/test_seed_generation_importer.py`
- Create: `code/fuzzer/hook_energy/seed_generation/__init__.py`
- Create: `code/fuzzer/hook_energy/seed_generation/models.py`
- Create: `code/fuzzer/hook_energy/seed_generation/importer.py`

- [ ] **Step 1: Write the failing test**

```python
import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.importer import HookSeedImporter


def build_callback(
    callback_id: str,
    hook_name: str,
    *,
    auth_mode: str,
) -> dict:
    return {
        "callback_id": callback_id,
        "hook_name": hook_name,
        "callback_name": f"{hook_name}_handler",
        "status": "uncovered",
        "is_active": True,
        "direct_http_supported": True,
        "generation_status": "supported_http_seed",
        "seed_priority": "highest",
        "target_family": "wp_ajax" if auth_mode == "authenticated" else "wp_ajax_nopriv",
        "source_file": "/var/www/html/wp-content/plugins/shop-demo/shop-demo.php",
        "source_line": 200,
        "accepted_args": 1,
        "seed": {
            "method": "POST",
            "path": "/wp-admin/admin-ajax.php",
            "content_type": "application/x-www-form-urlencoded",
            "body": {"action": hook_name.split("_", 2)[-1]},
            "auth_mode": auth_mode,
        },
    }


class HookSeedImporterReplayableTests(unittest.TestCase):
    def test_importer_splits_replayable_callbacks_by_auth_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps(
                    {
                        "summary": {"direct_http_seed_candidates": 2},
                        "callbacks": [
                            build_callback("cb-auth", "wp_ajax_shop_demo_refresh_panel", auth_mode="authenticated"),
                            build_callback("cb-public", "wp_ajax_nopriv_shop_demo_public_ping", auth_mode="unauth-capable"),
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(
                json.dumps({"suggested_seeds": []}),
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(len(result.authenticated_queue), 1)
            self.assertEqual(len(result.unauthenticated_queue), 1)
            self.assertEqual(result.authenticated_queue[0].auth_mode, "authenticated")
            self.assertEqual(result.unauthenticated_queue[0].auth_mode, "unauth-capable")
            self.assertEqual(result.authenticated_queue[0].path, "/wp-admin/admin-ajax.php")
            self.assertEqual(result.unauthenticated_queue[0].body["action"], "shop_demo_public_ping")
```

- [ ] **Step 2: Run test to verify it fails**

Run from `C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer`:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterReplayableTests.test_importer_splits_replayable_callbacks_by_auth_mode -v
```

Expected: `FAIL` or `ERROR` because `hook_energy.seed_generation.importer` does not exist yet.

- [ ] **Step 3: Write minimal implementation**

`code/fuzzer/hook_energy/seed_generation/models.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportedSeedRequest:
    request_id: str
    source: str
    http_method: str
    path: str
    content_type: str
    body: dict[str, Any]
    query_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    cookies: dict[str, Any] = field(default_factory=dict)
    auth_mode: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportedSeedResult:
    authenticated_queue: list[ImportedSeedRequest] = field(default_factory=list)
    unauthenticated_queue: list[ImportedSeedRequest] = field(default_factory=list)
    manual_analysis_queue: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
```

`code/fuzzer/hook_energy/seed_generation/importer.py`

```python
from __future__ import annotations

import json
from pathlib import Path

from .models import ImportedSeedRequest, ImportedSeedResult


class HookSeedImporter:
    def __init__(self, *, handoff_doc: Path, hook_gap_report: Path, suggested_seeds: Path) -> None:
        self.handoff_doc = Path(handoff_doc)
        self.hook_gap_report = Path(hook_gap_report)
        self.suggested_seeds = Path(suggested_seeds)

    def import_from_handoff(self) -> ImportedSeedResult:
        payload = json.loads(self.hook_gap_report.read_text(encoding="utf-8"))
        result = ImportedSeedResult()

        for callback in payload.get("callbacks", []):
            if not self._is_replayable(callback):
                continue

            imported = ImportedSeedRequest(
                request_id=f"seed-import-{callback['callback_id']}",
                source="external-hook-gap-report",
                http_method=callback["seed"]["method"],
                path=callback["seed"]["path"],
                content_type=callback["seed"]["content_type"],
                body=dict(callback["seed"]["body"]),
                auth_mode=callback["seed"]["auth_mode"],
                metadata={
                    "hook_name": callback["hook_name"],
                    "callback_id": callback["callback_id"],
                    "callback_name": callback["callback_name"],
                    "seed_priority": callback["seed_priority"],
                    "target_family": callback["target_family"],
                },
            )

            if imported.auth_mode == "authenticated":
                result.authenticated_queue.append(imported)
            else:
                result.unauthenticated_queue.append(imported)

        return result

    def _is_replayable(self, callback: dict) -> bool:
        return (
            callback.get("status") == "uncovered"
            and callback.get("is_active") is True
            and callback.get("direct_http_supported") is True
            and callback.get("generation_status") == "supported_http_seed"
            and callback.get("seed") is not None
        )
```

`code/fuzzer/hook_energy/seed_generation/__init__.py`

```python
from .importer import HookSeedImporter
from .models import ImportedSeedRequest, ImportedSeedResult

__all__ = ["HookSeedImporter", "ImportedSeedRequest", "ImportedSeedResult"]
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterReplayableTests.test_importer_splits_replayable_callbacks_by_auth_mode -v
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add code/fuzzer/tests/test_seed_generation_importer.py code/fuzzer/hook_energy/seed_generation/__init__.py code/fuzzer/hook_energy/seed_generation/models.py code/fuzzer/hook_energy/seed_generation/importer.py
git commit -m "feat: add replayable hook seed importer core"
```

## Task 2: Preserve Metadata and Manual Backlog Entries

**Files:**
- Modify: `code/fuzzer/tests/test_seed_generation_importer.py`
- Modify: `code/fuzzer/hook_energy/seed_generation/models.py`
- Modify: `code/fuzzer/hook_energy/seed_generation/importer.py`

- [ ] **Step 1: Write the failing tests**

```python
class HookSeedImporterBacklogTests(unittest.TestCase):
    def test_importer_preserves_metadata_and_backlogs_manual_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            replayable = build_callback("cb-auth", "admin_post_shop_demo_export_orders", auth_mode="authenticated")
            replayable["target_family"] = "admin_post"
            replayable["priority"] = 10

            manual_only = {
                "callback_id": "cb-manual",
                "hook_name": "template_redirect",
                "callback_name": "shop_render_test_ui",
                "status": "uncovered",
                "is_active": True,
                "direct_http_supported": False,
                "generation_status": "manual_analysis_required",
                "seed_priority": "low",
                "target_family": "internal_or_manual",
                "source_file": "/var/www/html/wp-content/plugins/shop-demo/shop-demo.php",
                "source_line": 321,
                "accepted_args": 1,
                "seed": None,
            }
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 1}, "callbacks": [replayable, manual_only]}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(json.dumps({"suggested_seeds": []}), encoding="utf-8")

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue[0].metadata["source_line"], 200)
            self.assertEqual(result.authenticated_queue[0].metadata["accepted_args"], 1)
            self.assertEqual(result.authenticated_queue[0].metadata["target_family"], "admin_post")
            self.assertEqual(len(result.manual_analysis_queue), 1)
            self.assertEqual(result.manual_analysis_queue[0]["callback_id"], "cb-manual")
            self.assertNotIn("request_id", result.manual_analysis_queue[0])
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterBacklogTests.test_importer_preserves_metadata_and_backlogs_manual_callbacks -v
```

Expected: `FAIL` because metadata fields and manual backlog behavior are incomplete.

- [ ] **Step 3: Write minimal implementation**

`code/fuzzer/hook_energy/seed_generation/models.py`

```python
@dataclass
class ManualAnalysisEntry:
    callback_id: str
    hook_name: str
    callback_name: str
    status: str
    is_active: bool
    direct_http_supported: bool
    generation_status: str
    seed_priority: str
    target_family: str
    source_file: str | None = None
    source_line: int | None = None
    accepted_args: int | None = None
```

`code/fuzzer/hook_energy/seed_generation/importer.py`

```python
from .models import ImportedSeedRequest, ImportedSeedResult, ManualAnalysisEntry


            imported = ImportedSeedRequest(
                request_id=f"seed-import-{callback['callback_id']}",
                source="external-hook-gap-report",
                http_method=callback["seed"]["method"],
                path=callback["seed"]["path"],
                content_type=callback["seed"]["content_type"],
                body=dict(callback["seed"]["body"]),
                auth_mode=callback["seed"]["auth_mode"],
                metadata={
                    "hook_name": callback["hook_name"],
                    "callback_id": callback["callback_id"],
                    "callback_name": callback["callback_name"],
                    "seed_priority": callback["seed_priority"],
                    "target_family": callback["target_family"],
                    "source_file": callback.get("source_file"),
                    "source_line": callback.get("source_line"),
                    "priority": callback.get("priority"),
                    "accepted_args": callback.get("accepted_args"),
                },
            )

        for callback in payload.get("callbacks", []):
            if self._is_replayable(callback):
                ...
            elif self._is_manual_only(callback):
                result.manual_analysis_queue.append(
                    ManualAnalysisEntry(
                        callback_id=callback["callback_id"],
                        hook_name=callback["hook_name"],
                        callback_name=callback["callback_name"],
                        status=callback["status"],
                        is_active=bool(callback["is_active"]),
                        direct_http_supported=bool(callback["direct_http_supported"]),
                        generation_status=callback["generation_status"],
                        seed_priority=callback["seed_priority"],
                        target_family=callback["target_family"],
                        source_file=callback.get("source_file"),
                        source_line=callback.get("source_line"),
                        accepted_args=callback.get("accepted_args"),
                    ).__dict__
                )

    def _is_manual_only(self, callback: dict) -> bool:
        return (
            callback.get("status") == "uncovered"
            and callback.get("is_active") is True
            and (
                callback.get("direct_http_supported") is False
                or callback.get("generation_status") == "manual_analysis_required"
            )
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterBacklogTests.test_importer_preserves_metadata_and_backlogs_manual_callbacks -v
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add code/fuzzer/tests/test_seed_generation_importer.py code/fuzzer/hook_energy/seed_generation/models.py code/fuzzer/hook_energy/seed_generation/importer.py
git commit -m "feat: preserve seed metadata and backlog manual callbacks"
```

## Task 3: Add Stale-Artifact Detection and Summary Generation

**Files:**
- Modify: `code/fuzzer/tests/test_seed_generation_importer.py`
- Create: `code/fuzzer/hook_energy/seed_generation/stale_check.py`
- Modify: `code/fuzzer/hook_energy/seed_generation/models.py`
- Modify: `code/fuzzer/hook_energy/seed_generation/importer.py`

- [ ] **Step 1: Write the failing test**

```python
class HookSeedImporterStaleArtifactTests(unittest.TestCase):
    def test_importer_warns_when_source_code_has_seed_hooks_but_report_has_zero_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            source_dir = root / "source"
            source_dir.mkdir()
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps({"summary": {"direct_http_seed_candidates": 0}, "callbacks": []}),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(json.dumps({"suggested_seeds": []}), encoding="utf-8")
            (source_dir / "pipeline.py").write_text(
                "wp_ajax_* -> POST /wp-admin/admin-ajax.php\\nadmin_post_* -> POST /wp-admin/admin-post.php\\n",
                encoding="utf-8",
            )
            (source_dir / "shop-demo.php").write_text(
                "add_action('wp_ajax_shop_demo_refresh_panel', 'shop_seed_ajax_refresh_panel');\\n"
                "add_action('admin_post_shop_demo_export_orders', 'shop_seed_admin_post_export_orders');\\n",
                encoding="utf-8",
            )

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
                source_pipeline=source_dir / "pipeline.py",
                source_plugin=source_dir / "shop-demo.php",
            )
            result = importer.import_from_handoff()

            self.assertEqual(result.authenticated_queue, [])
            self.assertEqual(result.unauthenticated_queue, [])
            self.assertTrue(any("stale" in warning.lower() for warning in result.warnings))
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterStaleArtifactTests.test_importer_warns_when_source_code_has_seed_hooks_but_report_has_zero_candidates -v
```

Expected: `FAIL` because the importer does not inspect source files or emit warnings yet.

- [ ] **Step 3: Write minimal implementation**

`code/fuzzer/hook_energy/seed_generation/stale_check.py`

```python
from __future__ import annotations

from pathlib import Path


def detect_stale_seed_artifacts(*, report_direct_candidates: int, source_pipeline: Path, source_plugin: Path) -> list[str]:
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
```

`code/fuzzer/hook_energy/seed_generation/importer.py`

```python
from .stale_check import detect_stale_seed_artifacts


    def __init__(
        self,
        *,
        handoff_doc: Path,
        hook_gap_report: Path,
        suggested_seeds: Path,
        source_pipeline: Path | None = None,
        source_plugin: Path | None = None,
    ) -> None:
        self.handoff_doc = Path(handoff_doc)
        self.hook_gap_report = Path(hook_gap_report)
        self.suggested_seeds = Path(suggested_seeds)
        self.source_pipeline = Path(source_pipeline) if source_pipeline is not None else None
        self.source_plugin = Path(source_plugin) if source_plugin is not None else None

    def import_from_handoff(self) -> ImportedSeedResult:
        payload = json.loads(self.hook_gap_report.read_text(encoding="utf-8"))
        result = ImportedSeedResult()
        ...
        if self.source_pipeline is not None and self.source_plugin is not None:
            result.warnings.extend(
                detect_stale_seed_artifacts(
                    report_direct_candidates=payload.get("summary", {}).get("direct_http_seed_candidates", 0),
                    source_pipeline=self.source_pipeline,
                    source_plugin=self.source_plugin,
                )
            )
        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterStaleArtifactTests.test_importer_warns_when_source_code_has_seed_hooks_but_report_has_zero_candidates -v
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add code/fuzzer/tests/test_seed_generation_importer.py code/fuzzer/hook_energy/seed_generation/stale_check.py code/fuzzer/hook_energy/seed_generation/models.py code/fuzzer/hook_energy/seed_generation/importer.py
git commit -m "feat: detect stale external seed artifacts"
```

## Task 4: Write Artifact Files and Primary-Truth Error Handling

**Files:**
- Modify: `code/fuzzer/tests/test_seed_generation_importer.py`
- Modify: `code/fuzzer/hook_energy/seed_generation/models.py`
- Modify: `code/fuzzer/hook_energy/seed_generation/importer.py`
- Modify: `code/fuzzer/hook_energy/__init__.py`

- [ ] **Step 1: Write the failing tests**

```python
class HookSeedImporterOutputTests(unittest.TestCase):
    def test_importer_writes_expected_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            output_dir = root / "seed-output"
            (handoff_dir / "hook_gap_report.json").write_text(
                json.dumps(
                    {
                        "summary": {"direct_http_seed_candidates": 1},
                        "callbacks": [
                            build_callback("cb-public", "wp_ajax_nopriv_shop_demo_public_ping", auth_mode="unauth-capable")
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (handoff_dir / "suggested_seeds.json").write_text(json.dumps({"suggested_seeds": []}), encoding="utf-8")

            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "hook_gap_report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            importer.write_artifacts(output_dir)

            self.assertTrue((output_dir / "imported_unauth_seeds.json").exists())
            self.assertTrue((output_dir / "imported_auth_seeds.json").exists())
            self.assertTrue((output_dir / "manual_analysis_queue.json").exists())
            self.assertTrue((output_dir / "import_summary.json").exists())

    def test_importer_fails_when_primary_hook_gap_report_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            handoff_dir = root / "handoff"
            handoff_dir.mkdir()
            importer = HookSeedImporter(
                handoff_doc=handoff_dir / "SEED_HANDOFF_FOR_AGENTS.md",
                hook_gap_report=handoff_dir / "missing-hook-gap-report.json",
                suggested_seeds=handoff_dir / "suggested_seeds.json",
            )
            with self.assertRaises(FileNotFoundError):
                importer.import_from_handoff()
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python -m unittest tests.test_seed_generation_importer.HookSeedImporterOutputTests -v
```

Expected: `FAIL` because artifact writing and primary-input validation are not implemented.

- [ ] **Step 3: Write minimal implementation**

`code/fuzzer/hook_energy/seed_generation/models.py`

```python
    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "source": self.source,
            "http_method": self.http_method,
            "path": self.path,
            "content_type": self.content_type,
            "body": self.body,
            "query_params": self.query_params,
            "headers": self.headers,
            "cookies": self.cookies,
            "auth_mode": self.auth_mode,
            "metadata": self.metadata,
        }
```

`code/fuzzer/hook_energy/seed_generation/importer.py`

```python
    def import_from_handoff(self) -> ImportedSeedResult:
        if not self.hook_gap_report.exists():
            raise FileNotFoundError(f"Missing primary handoff file: {self.hook_gap_report}")

        payload = json.loads(self.hook_gap_report.read_text(encoding="utf-8"))
        callbacks = payload.get("callbacks")
        if not isinstance(callbacks, list):
            raise ValueError("hook_gap_report.json must contain a callbacks array")
        ...

    def write_artifacts(self, output_dir: Path) -> ImportedSeedResult:
        result = self.import_from_handoff()
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        (output_dir / "imported_unauth_seeds.json").write_text(
            json.dumps([item.to_dict() for item in result.unauthenticated_queue], indent=2),
            encoding="utf-8",
        )
        (output_dir / "imported_auth_seeds.json").write_text(
            json.dumps([item.to_dict() for item in result.authenticated_queue], indent=2),
            encoding="utf-8",
        )
        (output_dir / "manual_analysis_queue.json").write_text(
            json.dumps(result.manual_analysis_queue, indent=2),
            encoding="utf-8",
        )
        (output_dir / "import_summary.json").write_text(
            json.dumps(
                {
                    "authenticated_count": len(result.authenticated_queue),
                    "unauthenticated_count": len(result.unauthenticated_queue),
                    "manual_analysis_count": len(result.manual_analysis_queue),
                    "warnings": result.warnings,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return result
```

`code/fuzzer/hook_energy/__init__.py`

```python
from .seed_generation import HookSeedImporter

__all__ = [
    ...
    "HookSeedImporter",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
python -m unittest tests.test_seed_generation_importer -v
```

Expected: all seed-generation tests `OK`

- [ ] **Step 5: Commit**

```bash
git add code/fuzzer/tests/test_seed_generation_importer.py code/fuzzer/hook_energy/seed_generation/__init__.py code/fuzzer/hook_energy/seed_generation/models.py code/fuzzer/hook_energy/seed_generation/stale_check.py code/fuzzer/hook_energy/seed_generation/importer.py code/fuzzer/hook_energy/__init__.py
git commit -m "feat: write imported hook seed artifacts"
```

## Self-Review

- Spec coverage:
  - External handoff reading: Task 1
  - Replayable filtering from `hook_gap_report.json`: Task 1
  - Metadata preservation: Task 2
  - Manual-analysis queue: Task 2
  - Stale-artifact warnings: Task 3
  - Output artifact writing: Task 4
  - Primary-truth validation and missing-input failure: Task 4
- Placeholder scan:
  - No `TODO`, `TBD`, or "similar to previous task" references remain.
- Type consistency:
  - `HookSeedImporter`, `ImportedSeedRequest`, `ImportedSeedResult`, and `ManualAnalysisEntry` names are consistent across all tasks.

