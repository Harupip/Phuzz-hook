"""Validate and save the request and Zend artifacts of a replay."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from online_linked.coordination.errors import ReplayArtifactError


def save_replay_artifacts(
    row: Mapping[str, Any], request_dir: Path, zend_dir: Path,
    *, strict_correlation: bool | None,
    load_request: Callable[[str], Any],
    load_zend: Callable[[str], Any],
    list_zend: Callable[[], set[str]],
    write_json: Callable[[Path, Any], None],
) -> None:
    if strict_correlation is None:
        strict_correlation = bool(row.get("_strict_correlation", True))
    names = set()
    matched = str(row.get("matched_artifact") or "")
    if matched:
        names.add(matched)
    names.update(str(name) for name in row.get("request_artifacts", []) if str(name))
    for name in names:
        if Path(name).name != name:
            if strict_correlation:
                raise ReplayArtifactError("id_correlation", "artifact name is not a file name")
            continue
        payload = row.get("request_payload") if name == matched else None
        if payload is None:
            try:
                payload = load_request(name)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ReplayArtifactError("sender_payload", "request payload loader failed") from exc
        if strict_correlation:
            _validate_artifact_payload(payload, name, row, zend=False)
        try:
            write_json(request_dir / name, payload)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ReplayArtifactError("request_write", "request artifact write failed") from exc
        zend_name = str(row.get("zend_artifact") or "") if name == matched else ""
        if zend_name and Path(zend_name).name == zend_name:
            zend_payload = row.get("zend_payload")
            if zend_payload is None:
                try:
                    zend_payload = load_zend(zend_name)
                except (OSError, RuntimeError, ValueError) as exc:
                    raise ReplayArtifactError("sender_payload", "Zend payload loader failed") from exc
            if strict_correlation:
                _validate_artifact_payload(zend_payload, zend_name, row, zend=True)
            try:
                write_json(zend_dir / zend_name, zend_payload)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ReplayArtifactError("zend_write", "Zend artifact write failed") from exc
        else:
            if name != matched:
                continue
            if zend_name:
                if strict_correlation:
                    raise ReplayArtifactError("id_correlation", "Zend artifact name is not a file name")
                continue
            zend_names = list_zend()
            exact = [candidate for candidate in zend_names if Path(candidate).name == candidate and Path(candidate).stem == Path(name).stem]
            if len(exact) != 1:
                if strict_correlation:
                    raise ReplayArtifactError("id_correlation", "request and Zend artifact IDs do not match")
                continue
            try:
                zend_payload = load_zend(exact[0])
            except (OSError, RuntimeError, ValueError) as exc:
                raise ReplayArtifactError("sender_payload", "Zend payload loader failed") from exc
            if strict_correlation:
                _validate_artifact_payload(zend_payload, exact[0], row, zend=True)
            try:
                write_json(zend_dir / exact[0], zend_payload)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ReplayArtifactError("zend_write", "Zend artifact write failed") from exc

def _validate_artifact_payload(
    payload: Any, name: str, row: Mapping[str, Any], *, zend: bool,
) -> None:
    if not isinstance(payload, Mapping):
        raise ReplayArtifactError("sender_payload", "artifact payload is missing")
    if str(payload.get("request_id") or "") != Path(name).stem:
        raise ReplayArtifactError("id_correlation", "artifact request ID does not match its name")
    expected_run_id = str(row.get("legacy_run_id") or "")
    actual_run_id = str(
        (payload.get("run_id") if zend else None)
        or payload.get("legacy_run_id")
        or ""
    )
    if expected_run_id and actual_run_id and actual_run_id != expected_run_id:
        raise ReplayArtifactError("id_correlation", "artifact run ID does not match the replay")
