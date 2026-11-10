"""Pure runtime callback discovery helpers for the online-linked coordinator."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def foreign_callback(request_payload: Mapping[str, Any], version: Mapping[str, Any]) -> tuple[str, str] | None:
    """Return the explicit callback/hook when the request names one other than the version's."""
    explicit_callback = str(request_payload.get("callback_id") or "").strip()
    explicit_hook = str(request_payload.get("hook_name") or "").strip()
    if (explicit_callback and explicit_callback != str(version.get("callback_id") or "")) or (
        explicit_hook and explicit_hook != str(version.get("hook_name") or "")
    ):
        return explicit_callback, explicit_hook
    return None


def registered_child_callback(
    fallback_id: Any,
    raw_callback: Any,
    *,
    parent_callback_id: str,
    parent_hook_name: str,
    request_id: str,
    plugin_slug: str,
) -> tuple[dict[str, Any], str, str] | None:
    """Return (callback, callback_id, hook_name) for a callback registered inside the parent."""
    if not isinstance(raw_callback, Mapping):
        return None
    callback = dict(raw_callback)
    callback_id = str(callback.get("callback_id") or fallback_id).strip()
    hook_name = str(callback.get("hook_name") or "").strip()
    if not callback_id or not hook_name or callback_id == parent_callback_id:
        return None
    if not callback.get("registered_inside_callback"):
        return None
    parent_callback = callback.get("parent_callback") if isinstance(callback.get("parent_callback"), Mapping) else {}
    parent_ids = {
        str(callback.get("parent_callback_id") or "").strip(),
        str(parent_callback.get("callback_id") or "").strip(),
    }
    parent_hooks = {
        str(callback.get("parent_hook_name") or "").strip(),
        str(parent_callback.get("hook_name") or "").strip(),
    }
    if parent_callback_id not in parent_ids and parent_hook_name not in parent_hooks:
        return None
    callback.setdefault("callback_id", callback_id)
    callback.setdefault("request_id", request_id)
    callback.setdefault("target_plugin", plugin_slug)
    return callback, callback_id, hook_name


def merge_registry_callback(registry: dict[str, Any], callback: Mapping[str, Any]) -> bool:
    """Merge one callback into ``registry`` in place; True only when a registration was added."""
    callback_id = str(callback.get("callback_id") or "").strip()
    canonical = str(callback.get("callback_repr") or callback_id).strip()
    if not callback_id or not canonical:
        return False
    callback_map = registry.setdefault("callback_map", {})
    if not isinstance(callback_map, dict):
        callback_map = {}
        registry["callback_map"] = callback_map
    callback_map[callback_id] = canonical
    registrations = registry.setdefault("registrations", [])
    if not isinstance(registrations, list):
        registrations = []
        registry["registrations"] = registrations
    if any(str(row.get("callback_id") or "") == callback_id for row in registrations if isinstance(row, Mapping)):
        return False
    registrations.append({
        "callback_id": callback_id,
        "callback": canonical,
        "canonical_callback": canonical,
        "callback_type": "static_method" if "::" in canonical else "function",
    })
    return True
