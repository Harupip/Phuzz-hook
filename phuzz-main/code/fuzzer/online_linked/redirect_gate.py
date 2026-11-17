"""Conservative admission of redirects in the instrumented WordPress harness."""

import re
from collections.abc import Mapping
from hashlib import sha256
from urllib.parse import unquote, urljoin, urlsplit


def replay_http_admitted(payload, zend, *, callback_id, request_id, run_id, target, transport=None):
    response = payload.get('response') if isinstance(payload, Mapping) else None
    if not isinstance(response, Mapping) or (transport is not None and transport.get('error')):
        return False
    observed_status = transport.get('response_status') if transport is not None else None
    try:
        artifact_status = int(response['status_code'])
        status = int(observed_status) if observed_status is not None else artifact_status
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    if status != artifact_status:
        return False
    if 200 <= status < 300:
        return True

    location_hash = response.get('location_sha256')
    location_base = response.get('location_base')
    if transport is not None:
        # v0 has the shutdown header snapshot. Child replay also has the transport observation.
        location = transport.get('response_location')
        if observed_status is None or not isinstance(location, str) or not location:
            return False
        if sha256(location.encode('utf-8')).hexdigest() != location_hash:
            return False
        if location.split('#', 1)[0].split('?', 1)[0] != location_base:
            return False
    return verified_redirect(
        payload, callback_id=callback_id, request_id=request_id, run_id=run_id,
        status=status, location=location_base, location_sha256=location_hash, target=target, zend=zend,
    )


def _executed_callback(payload, callback_id):
    coverage = payload.get('hook_coverage') if isinstance(payload, Mapping) else None
    executed = coverage.get('executed_callbacks') if isinstance(coverage, Mapping) else None
    if not isinstance(executed, (Mapping, list)):
        return None
    entries = executed.items() if isinstance(executed, Mapping) else enumerate(executed)
    for key, entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get('callback_id') or key) != callback_id:
            continue
        try:
            if int(entry.get('executed_count')) > 0:
                return entry
        except (TypeError, ValueError):
            return None
    return None


def _has_post_guard_continuation(zend, *, request_id, run_id, callback, guard_reads=frozenset()):
    if not isinstance(zend, Mapping):
        return False
    if (zend.get('request_id') != request_id
            or (zend.get('run_id') or zend.get('legacy_run_id')) != run_id):
        return False
    callback_repr = str(callback.get('callback_repr') or '')
    if not callback_repr or not isinstance(zend.get('events'), list):
        return False
    if not guard_reads:
        # wp_verify_nonce() alone gives no point in time: the plugin may read the nonce and its
        # business fields long before verifying. Without a referer guard read, stay blocked.
        return False
    guard_fields = frozenset(field for field, _, _ in guard_reads)
    guard_files = frozenset(file for _, file, _ in guard_reads)
    nonce_seen = False
    for event in zend['events']:
        if not isinstance(event, Mapping):
            continue
        context = event.get('callback_context')
        if not isinstance(context, Mapping) or context.get('attributed') is not True:
            continue
        if str(context.get('root_callback') or '').replace('->', '::') != callback_repr.replace('->', '::'):
            continue
        path = event.get('path')
        operation = event.get('operation')
        # Only the referer guard's own read (field, file, line) marks when the guard ran, so a
        # same-named read earlier in the callback cannot stand in for it.
        if operation == 'read' and _read_key(event) in guard_reads:
            nonce_seen = True
            continue
        # shortcut: endpoints with no post-nonce input access need a callback-completion event.
        if (nonce_seen and operation in {'read', 'isset'} and not _is_nonce_path(path, guard_fields)
                and _basename(event.get('file')) not in guard_files):
            return True
    return False


def _is_nonce_path(path, nonce_fields=frozenset()):
    if not isinstance(path, list) or not path:
        return False
    name = str(path[-1])
    # Same name rule the config exporter uses, plus fields a referer guard actually read (e.g. `security`).
    return 'nonce' in name.lower() or name in nonce_fields


def _basename(file):
    # Compare by name only: the container may resolve the override path through a symlink.
    return re.split(r'[\\/]', file)[-1] if isinstance(file, str) and file else None


def _read_key(event):
    path = event.get('path')
    if not isinstance(path, list) or not path:
        return None
    try:
        return str(path[-1]), _basename(event.get('file')), int(event.get('line'))
    except (TypeError, ValueError):
        return None


def _guard_nonce_reads(payload, callback_id):
    events = payload.get('guard_redirect_events') if isinstance(payload, Mapping) else None
    reads = set()
    for event in events if isinstance(events, list) else []:
        if (not isinstance(event, Mapping) or event.get('kind') != 'nonce_field'
                or event.get('callback_id') != callback_id):
            continue
        key = (event.get('field'), _basename(event.get('file')), event.get('line'))
        if isinstance(key[0], str) and key[1] and isinstance(key[2], int):
            reads.add(key)
    return frozenset(reads)


def verified_redirect(payload, *, callback_id, request_id, run_id, status, location, target,
                      zend=None, location_sha256=None):
    if not isinstance(payload, Mapping) or not callback_id or not request_id or not run_id:
        return False
    # Same run identity rule as evidence correlation: legacy_run_id first, then run_id.
    if (payload.get('request_id') != request_id
            or (payload.get('legacy_run_id') or payload.get('run_id')) != run_id
            or payload.get('auth_context') != 'authenticated' or payload.get('errors')):
        return False
    if payload.get('callback_id') and payload.get('callback_id') != callback_id:
        return False
    callback = _executed_callback(payload, callback_id)
    if callback is None or not _has_post_guard_continuation(
            zend, request_id=request_id, run_id=run_id, callback=callback,
            guard_reads=_guard_nonce_reads(payload, callback_id)):
        return False
    if not isinstance(target, str) or not isinstance(location, str) or not location:
        return False
    response = payload.get('response')
    try:
        if int(status) not in {301, 302, 303, 307, 308} or int(response['status_code']) != int(status):
            return False
        origin, destination = urlsplit(target), urlsplit(urljoin(target, location))
        if (origin.scheme not in {'http', 'https'} or not origin.netloc
                or (origin.scheme, origin.netloc) != (destination.scheme, destination.netloc)
                or 'wp-login.php' in unquote(destination.path).lower().split('/')):
            return False
    except (TypeError, ValueError, KeyError, OverflowError):
        return False
    if location_sha256 is None:
        location_sha256 = sha256(location.encode('utf-8')).hexdigest()
    if not isinstance(location_sha256, str) or len(location_sha256) != 64:
        return False
    events = payload.get('guard_redirect_events')
    if not isinstance(events, list):
        return False
    guards = set()
    redirect = None
    redirect_index = None
    for index, event in enumerate(events):
        if not isinstance(event, Mapping) or event.get('callback_id') != callback_id:
            continue
        if event.get('kind') == 'guard':
            # Guard events exist only for overridden WP checks; auth_context above proves they passed.
            function = event.get('function')
            if not isinstance(function, str):
                return False
            guards.add(function)
        elif event.get('kind') == 'redirect':
            if redirect is not None:
                return False
            redirect = event
            redirect_index = index
    if redirect is None or redirect_index is None or 'current_user_can' not in guards:
        return False
    if any(
        isinstance(event, Mapping) and event.get('callback_id') == callback_id
        and event.get('kind') == 'guard' and index > redirect_index
        for index, event in enumerate(events)
    ):
        return False
    if not guards & {'wp_verify_nonce', 'check_ajax_referer', 'check_admin_referer'}:
        return False
    # This proves observed WP checks under overrides, not production authentication.
    return (redirect.get('status') == int(status) and redirect.get('location_sha256') == location_sha256
            and redirect.get('function') == 'wp_redirect' and redirect.get('mode') == 'observed')
