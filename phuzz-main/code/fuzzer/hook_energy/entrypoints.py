from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


# WordPress AJAX: POST admin-ajax.php with action in the form body.
_AJAX_RULES = (
    {
        "prefix": "wp_ajax_nopriv_",
        "entry_type": "ajax_unauthenticated",
        "path": "/wp-admin/admin-ajax.php",
        "method": "POST",
        "param_target": "body_params",
        "auth_required": False,
        "reason": "WordPress AJAX nopriv hook maps directly to admin-ajax.php?action=<action>",
    },
    {
        "prefix": "wp_ajax_",
        "entry_type": "ajax_authenticated",
        "path": "/wp-admin/admin-ajax.php",
        "method": "POST",
        "param_target": "body_params",
        "auth_required": True,
        "reason": "WordPress AJAX hook maps directly to admin-ajax.php?action=<action>",
    },
)

# Admin Post: POST admin-post.php with action in the form body.
_ADMIN_POST_RULES = (
    {
        "prefix": "admin_post_nopriv_",
        "entry_type": "admin_post_unauthenticated",
        "path": "/wp-admin/admin-post.php",
        "method": "POST",
        "param_target": "body_params",
        "auth_required": False,
        "reason": "WordPress admin-post nopriv hook maps directly to admin-post.php?action=<action>",
    },
    {
        "prefix": "admin_post_",
        "entry_type": "admin_post_authenticated",
        "path": "/wp-admin/admin-post.php",
        "method": "POST",
        "param_target": "body_params",
        "auth_required": True,
        "reason": "WordPress admin-post hook maps directly to admin-post.php?action=<action>",
    },
)

# Admin Action: GET admin.php with action in the query string.
_ADMIN_ACTION_RULES = (
    {
        "prefix": "admin_action_",
        "entry_type": "admin_action",
        "path": "/wp-admin/admin.php",
        "method": "GET",
        "param_target": "query_params",
        "auth_required": True,
        "reason": "WordPress admin action hook maps directly to admin.php?action=<action>",
    },
)

# Login Form: POST wp-login.php with action in the query string.
_LOGIN_FORM_RULES = (
    {
        "prefix": "login_form_",
        "entry_type": "login_form",
        "path": "/wp-login.php",
        "method": "POST",
        "param_target": "query_params",
        "auth_required": False,
        "reason": "WordPress login form hook maps directly to wp-login.php?action=<action>",
    },
)

DIRECT_HTTP_RULES = _AJAX_RULES + _ADMIN_POST_RULES + _ADMIN_ACTION_RULES + _LOGIN_FORM_RULES

# Heartbeat: exact hook names map to admin-ajax.php?action=heartbeat.
DIRECT_HTTP_EXACT_RULES = {
    "heartbeat_received": {
        "entry_type": "heartbeat_authenticated",
        "path": "/wp-admin/admin-ajax.php",
        "method": "POST",
        "param_target": "body_params",
        "action": "heartbeat",
        "auth_required": True,
        "reason": "WordPress authenticated heartbeat hook maps directly to admin-ajax.php?action=heartbeat",
    },
    "heartbeat_nopriv_received": {
        "entry_type": "heartbeat_unauthenticated",
        "path": "/wp-admin/admin-ajax.php",
        "method": "POST",
        "param_target": "body_params",
        "action": "heartbeat",
        "auth_required": False,
        "reason": "WordPress unauthenticated heartbeat hook maps directly to admin-ajax.php?action=heartbeat",
    },
}


def direct_http_details(hook_name: str | None, metadata: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    # REST route: runtime already resolved register_rest_route() into entrypoint_type=rest_route.
    rest_template = rest_http_template(metadata or {})
    if rest_template is not None and _is_first_class_rest_route(hook_name, metadata or {}):
        return {
            "entry_type": "rest_route",
            "action": None,
            "http_template": rest_template,
            "auth_required": _rest_auth_required(metadata or {}),
            "confidence": "high",
            "reason": "WordPress REST route maps directly to /wp-json/<namespace>/<route>",
        }

    if not hook_name:
        return None

    # Heartbeat: exact hook names beat prefix rules.
    exact_rule = DIRECT_HTTP_EXACT_RULES.get(hook_name)
    if exact_rule is not None:
        return _build_direct_details(exact_rule, exact_rule["action"])

    # Prefix rules: order matters, nopriv_* must be checked before authenticated prefixes.
    for rule in DIRECT_HTTP_RULES:
        prefix = str(rule["prefix"])
        if hook_name.startswith(prefix):
            return _build_direct_details(rule, hook_name.removeprefix(prefix))
    return None


def seed_template_for_callback(
    hook_name: str,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    # REST route seeds target /wp-json and never carry an action parameter.
    if _is_first_class_rest_route(hook_name, metadata or {}):
        return rest_seed_template(metadata or {})

    details = direct_http_details(hook_name)
    if details is None:
        return None

    http_template = details["http_template"]
    entrypoint_type = "heartbeat" if hook_name in DIRECT_HTTP_EXACT_RULES else details["entry_type"]
    return {
        "method": http_template["method"],
        "path": http_template["path"],
        "content_type": "application/x-www-form-urlencoded",
        "body": dict(http_template.get("body_params") or {}),
        "query_params": dict(http_template.get("query_params") or {}),
        "auth_mode": "authenticated" if details["auth_required"] else "unauth-capable",
        "fixed_params": ["action"] if details.get("action") else [],
        "entrypoint_type": entrypoint_type,
    }


def rest_seed_template(metadata: Mapping[str, Any]) -> dict[str, Any] | None:
    # REST config export preserves all route methods, while replay uses the first one.
    template = rest_http_template(metadata)
    if template is None:
        return None
    methods = _normalize_methods(metadata.get("methods", metadata.get("method", template["method"])))
    if not methods:
        methods = [template["method"]]
    return {
        "method": methods[0],
        "methods": methods,
        "path": template["path"],
        "content_type": "application/json",
        "body": {},
        "auth_mode": "authenticated" if _rest_auth_required(metadata) else "unauth-capable",
        "fixed_params": [],
        "entrypoint_type": "rest_route",
    }


def rest_http_template(metadata: Mapping[str, Any]) -> dict[str, Any] | None:
    # REST route metadata comes from the WordPress register_rest_route() hook recorder.
    # Accepted shapes: entrypoint_type=rest_route, hook_name=rest_route:namespace/path,
    # or rest_api_init records that still carry namespace/route metadata.
    route = str(metadata.get("rest_route") or metadata.get("route") or "").strip("/")
    namespace = str(metadata.get("namespace") or "").strip("/")
    if not route:
        hook_name = str(metadata.get("hook_name") or "")
        if hook_name.startswith("rest_route:"):
            route = hook_name.removeprefix("rest_route:").strip("/")
    if not route:
        return None
    if namespace and not route.startswith(f"{namespace}/"):
        route = f"{namespace}/{route}"

    methods = _normalize_methods(metadata.get("methods", metadata.get("method", "GET")))
    method = methods[0] if methods else "GET"
    return {"method": method, "path": f"/wp-json/{route}", "query_params": {}, "body_params": {}}


def _build_direct_details(rule: Mapping[str, Any], action: str) -> dict[str, Any]:
    query_params: dict[str, str] = {}
    body_params: dict[str, str] = {}
    if rule["param_target"] == "query_params":
        query_params["action"] = action
    else:
        body_params["action"] = action

    return {
        "entry_type": rule["entry_type"],
        "action": action,
        "http_template": {
            "method": rule["method"],
            "path": rule["path"],
            "query_params": query_params,
            "body_params": body_params,
        },
        "auth_required": rule["auth_required"],
        "confidence": "high",
        "reason": rule["reason"],
    }


def _is_first_class_rest_route(hook_name: str | None, metadata: Mapping[str, Any]) -> bool:
    return metadata.get("entrypoint_type") == "rest_route" or str(hook_name or "").startswith("rest_route:")


def _rest_auth_required(metadata: Mapping[str, Any]) -> bool:
    permission_callback = str(metadata.get("permission_callback") or "").strip()
    return permission_callback not in {"", "__return_true"}


def _normalize_methods(value: Any) -> list[str]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        raw_items = list(value)
    else:
        raw_items = [value]
    return [str(item).upper() for item in raw_items if str(item or "").strip()]
