"""Conservative admission of redirects in the instrumented WordPress harness."""

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


def _has_post_guard_continuation(zend, *, request_id, run_id, callback):
    if not isinstance(zend, Mapping):
        return False
    if (zend.get('request_id') != request_id
            or (zend.get('run_id') or zend.get('legacy_run_id')) != run_id):
        return False
    callback_repr = str(callback.get('callback_repr') or '')
    if not callback_repr or not isinstance(zend.get('events'), list):
        return False
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
        if operation == 'read' and path == ['nonce']:
            nonce_seen = True
            continue
        # shortcut: endpoints with no post-nonce input access need a callback-completion event.
        if nonce_seen and operation in {'read', 'isset'} and path != ['nonce']:
            return True
    return False


def verified_redirect(payload, *, callback_id, request_id, run_id, status, location, target,
                      zend=None, location_sha256=None):
    if not isinstance(payload, Mapping) or not callback_id or not request_id or not run_id:
        return False
    if (payload.get('request_id') != request_id or payload.get('run_id') != run_id
            or payload.get('auth_context') != 'authenticated' or payload.get('errors')):
        return False
    if payload.get('callback_id') and payload.get('callback_id') != callback_id:
        return False
    callback = _executed_callback(payload, callback_id)
    if callback is None or not _has_post_guard_continuation(
            zend, request_id=request_id, run_id=run_id, callback=callback):
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
            if event.get('passed') is not True or event.get('mode') != 'override':
                return False
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
