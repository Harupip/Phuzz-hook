# Phase 11B CF7 authenticated REST investigation

## Scope and initial repository state

This proof is limited to the local Docker WordPress environment and the pinned
`contact-form-7.5.7.7.zip` fixture. No external target or credential is used.

Initial inspection was run before this workspace was created:

- branch: `feature/http-method-inference`
- `git status --short`: existing user changes were present in fuzzer,
  instrumentation, Phase 9/10/11 research, and other untracked research files.
  They are not reset, cleaned, stashed, or otherwise changed by this proof.
- `git log --oneline -20`: recorded the current `c1723d0 Merge HTTP method
  inference hardening` head and its preceding history.

## Pinned CF7 source contract

The archive SHA-256 already recorded by Phase 11 is
`913583ac1d590daac3971791d6b5441d4d4293c60ff4ec62978c88f4d45a4461`.

The selected route is the least-invasive authenticated CF7 route:

- source: `contact-form-7/includes/rest-api.php:18-34` in the pinned archive
- namespace: `contact-form-7/v1` (`:14`)
- route pattern: `/contact-forms` (`:19-20`)
- declared method: `WP_REST_Server::READABLE` (`:23`), resolved at runtime to
  `GET`
- callback: `WPCF7_REST_Controller::get_contact_forms` (`:24`)
- permission callback: the closure at `:25-33`, which permits only
  `current_user_can( 'wpcf7_read_contact_forms' )` (`:26`). CF7 maps that
  meta-capability to the actual minimum WordPress primitive `edit_posts` in
  `contact-form-7/includes/capabilities.php:4-22`; the allowed local user gets
  only `edit_posts`, while the denied user gets neither it nor a broader role.
- parameter reads: `WP_REST_Request::get_param()` for `per_page`, `offset`,
  `order`, `orderby`, and `search` in `get_contact_forms()` (`:143-171`);
  this proof uses `search` with a synthetic marker.

The selected GET is read-only. It needs no CF7 object fixture and its callback
does not perform a write. The dedicated local subscriber-equivalent test user
is granted only `edit_posts`, the capability CF7 actually checks after
meta-capability mapping.

## WordPress cookie REST authentication

The proof will perform a real local `wp-login.php` form login, retain only the
session cookie in a process-local cookie jar, and fetch a fresh `wp_rest` nonce
from the authenticated local session. WordPress REST cookie authentication
expects that nonce in the `X-WP-Nonce` header (or `_wpnonce`); this run uses the
header and redacts the nonce and cookie values in every persistent artifact.

## Existing pipeline and boundary

Existing HookPhuzz route capture is installed through
`phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php:1135-1144`.
It records REST metadata through `__uopz_register_rest_route()` (`:776-801`),
including namespace, route, normalized method list, and permission callback.
Method resolution is production code in
`phuzz-main/code/fuzzer/hook_energy/method_resolution.py:19-103`; route
materialization is in `hook_energy/rest_routes.py:9-42`; config export is in
`hook_energy/seed_generation/config_exporter.py:14-72`.

Phase 11A already proves method resolution, materialization, exporter, and
fresh-artifact isolation with its synthetic plugin. Its direct replay harness
does not carry an authenticated cookie jar or REST nonce. The existing generic
seed validator likewise only sends template headers and body/query parameters;
it has no local login/nonce lifecycle.

The previous Phase 11B blocker is exact: the retained Phase 10 CF7 request
script sent `curl -G` against the selected route
(`research/hookphuzz-opcode/phase10-cf7-rest/wordpress/rest-request.sh:15-19`)
and its Phase 10 login helper synthesized an auth cookie through WP-CLI rather
than logging in through `wp-login.php`
(`wordpress/login-session.sh:4-8`). It neither obtained nor supplied an
`X-WP-Nonce`; therefore the real CF7 permission callback could not be proved
on the requested legitimate cookie-authenticated REST boundary. Phase 10
records this as authentication-blocked in
`research/hookphuzz-opcode/phase11-rest-method-generalization/results/phase11b.json:6`.

## Missing piece and implementation decision

No Phase 11A resolver change is indicated: the real route declares one
read-only method and the production resolver must resolve it as `GET`.
The missing piece is an isolated local authentication-aware generated-config
replay adapter: it must preserve the production-exported method/path/query
sections while adding the ephemeral cookie and freshly acquired `X-WP-Nonce`.
It will be implemented only in this Phase 11B workspace, together with a
callback observer tied to the actual CF7 method. The observer will write an
atomic current-request artifact only when the expected request ID is present;
it will not alter WordPress, CF7, permission checks, or HookPhuzz production
method-resolution behavior.
