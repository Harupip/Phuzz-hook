import unittest
from hashlib import sha256

from online_linked.redirect_gate import verified_redirect


REDIRECT_LOCATION = 'http://web/wp-admin/admin.php?page=forms'
# Where the check_ajax_referer() override reads the nonce field, as Zend and the guard both report it.
GUARD_FILE, GUARD_LINE = '/var/www/fuzzer/overrides.d/99-wordpress.php', 26


def zend_reads(callback_repr):
    """The referer guard reads `nonce`, then the callback reads a business field."""
    context = {'attributed': True, 'root_callback': callback_repr}
    return [
        {'source': 'REQUEST', 'path': ['nonce'], 'operation': 'read', 'file': GUARD_FILE, 'line': GUARD_LINE,
         'callback_context': dict(context)},
        {'source': 'GET', 'path': ['client_id'], 'operation': 'read', 'file': '/p/plugin.php', 'line': 9,
         'callback_context': dict(context)},
    ]


def add_redirect_evidence(request, zend, *, callback_id, callback_repr, location=REDIRECT_LOCATION, status=302):
    location_hash = sha256(location.encode('utf-8')).hexdigest()
    request.update(
        response={'status_code': status, 'location_base': location.split('?', 1)[0],
                  'location_sha256': location_hash},
        hook_coverage={'executed_callbacks': {callback_id: {
            'callback_id': callback_id, 'callback_repr': callback_repr, 'executed_count': 1,
        }}},
        guard_redirect_events=[
            {'kind': 'guard', 'function': 'current_user_can', 'callback_id': callback_id},
            {'kind': 'guard', 'function': 'check_ajax_referer', 'callback_id': callback_id},
            {'kind': 'nonce_field', 'function': 'check_ajax_referer', 'field': 'nonce',
             'file': '99-wordpress.php', 'line': GUARD_LINE, 'callback_id': callback_id},
            {'kind': 'redirect', 'function': 'wp_redirect', 'mode': 'observed',
             'callback_id': callback_id, 'status': status, 'location_sha256': location_hash},
        ],
    )
    zend['events'] = zend_reads(callback_repr)


class RedirectGateTests(unittest.TestCase):
    def proof(self):
        request = {
            'request_id': 'request', 'run_id': 'run', 'auth_context': 'authenticated',
        }
        add_redirect_evidence(request, {}, callback_id='cb', callback_repr='Fixture::callback')
        return request

    def zend(self):
        return {'request_id': 'request', 'run_id': 'run', 'events': zend_reads('Fixture::callback')}

    def check(self, payload, **kwargs):
        return verified_redirect(payload, callback_id='cb', request_id='request', run_id='run',
                                 status=302, location='http://web/wp-admin/admin.php?page=forms',
                                 target='http://web/wp-admin/admin-ajax.php', zend=self.zend(), **kwargs)

    def test_observed_override_checks_allow_same_request_redirect(self):
        self.assertTrue(self.check(self.proof()))

    def test_wp_verify_nonce_alone_never_admits_redirect(self):
        """$n = $_POST['nonce']; read business fields; wp_verify_nonce($n): no read marks when the guard ran."""
        p = self.proof()
        p['guard_redirect_events'] = [
            event for event in p['guard_redirect_events'] if event['kind'] != 'nonce_field'
        ]
        p['guard_redirect_events'][1]['function'] = 'wp_verify_nonce'
        for name in ('nonce', 'cn_nonce', '_wpnonce'):
            with self.subTest(name=name):
                zend = self.zend()
                zend['events'][0].update(path=[name], file='/p/plugin.php', line=5)
                self.assertFalse(verified_redirect(
                    p, callback_id='cb', request_id='request', run_id='run', status=302,
                    location='http://web/wp-admin/admin.php?page=forms',
                    target='http://web/wp-admin/admin-ajax.php', zend=zend,
                ))

    GUARD_READ = {'file': '/var/www/fuzzer/overrides.d/99-wordpress.php', 'line': 26}

    def guarded_check(self, events, nonce_field_event):
        p = self.proof()
        if nonce_field_event is not None:
            p['guard_redirect_events'].insert(0, nonce_field_event)
        zend = self.zend()
        ctx = zend['events'][0]['callback_context']
        zend['events'] = [{'source': 'POST', 'operation': 'read', 'callback_context': ctx, **event} for event in events]
        return verified_redirect(
            p, callback_id='cb', request_id='request', run_id='run', status=302,
            location='http://web/wp-admin/admin.php?page=forms',
            target='http://web/wp-admin/admin-ajax.php', zend=zend,
        )

    def test_referer_guard_field_counts_as_nonce_step(self):
        """check_ajax_referer('x', 'security'): the override's own read of `security` is the guard step."""
        field = {'kind': 'nonce_field', 'function': 'check_ajax_referer', 'field': 'security',
                 'file': '99-wordpress.php', 'line': 26, 'callback_id': 'cb'}
        events = [{'path': ['security'], **self.GUARD_READ}, {'path': ['client_id'], 'file': '/p/plugin.php', 'line': 9}]
        self.assertTrue(self.guarded_check(events, field))
        # Without the guard naming that read, `security` is just a business parameter.
        self.assertFalse(self.guarded_check(events, None))
        self.assertFalse(self.guarded_check(events, {**field, 'callback_id': 'other'}))
        self.assertFalse(self.guarded_check(events, {**field, 'line': 27}))

    def test_same_named_read_before_guard_is_not_the_guard_step(self):
        """read security -> read client_id -> guard reads security -> redirect must not pass."""
        field = {'kind': 'nonce_field', 'function': 'check_ajax_referer', 'field': 'security',
                 'file': '99-wordpress.php', 'line': 26, 'callback_id': 'cb'}
        events = [
            {'path': ['security'], 'file': '/p/plugin.php', 'line': 5},   # plugin, before guard
            {'path': ['client_id'], 'file': '/p/plugin.php', 'line': 6},  # business, before guard
            {'path': ['security'], **self.GUARD_READ},                    # the guard's own read
        ]
        self.assertFalse(self.guarded_check(events, field))
        # A business read after the guard's read is real continuation.
        self.assertTrue(self.guarded_check(events + [{'path': ['client_id'], 'file': '/p/plugin.php', 'line': 12}], field))

    def test_second_nonce_read_is_not_post_guard_continuation(self):
        """Reading another nonce field is still the guard, not logic that runs after it."""
        zend = self.zend()
        zend['events'][1]['path'] = ['_wpnonce']
        self.assertFalse(verified_redirect(
            self.proof(), callback_id='cb', request_id='request', run_id='run', status=302,
            location='http://web/wp-admin/admin.php?page=forms',
            target='http://web/wp-admin/admin-ajax.php', zend=zend,
        ))

    def test_missing_failed_wrong_callback_and_uncorrelated_proof_stay_blocked(self):
        for change in ('missing', 'wrong_callback', 'request', 'run', 'guest', 'status', 'location', 'order'):
            with self.subTest(change=change):
                p = self.proof()
                if change == 'missing': p['guard_redirect_events'].pop(1)
                elif change == 'wrong_callback': p['guard_redirect_events'][1]['callback_id'] = 'other'
                elif change == 'request': p['request_id'] = 'other'
                elif change == 'run': p['run_id'] = 'other'
                elif change == 'guest': p['auth_context'] = 'guest'
                elif change == 'status': p['response']['status_code'] = 403
                elif change == 'location': p['guard_redirect_events'][-1]['location_sha256'] = sha256(b'/different').hexdigest()
                elif change == 'order': p['guard_redirect_events'].reverse()
                self.assertFalse(self.check(p))

    def test_login_destination_and_untrusted_redirect_are_blocked(self):
        for location in ('/wp-login.php?redirect_to=foo', '/%77p-login.php',
                         '/wordpress/WP-login%2Ephp/extra', 'https://elsewhere.test/ok', ''):
            with self.subTest(location=location):
                p = self.proof()
                add_redirect_evidence(p, {}, callback_id='cb', callback_repr='Fixture::callback', location=location)
                self.assertFalse(verified_redirect(
                    p, callback_id='cb', request_id='request', run_id='run', status=302,
                    location=location, target='http://web/wp-admin/admin-ajax.php', zend=self.zend(),
                ))

    def test_callback_entry_alone_does_not_allow_redirect(self):
        p = self.proof()
        p['guard_redirect_events'] = []
        self.assertFalse(self.check(p))

    def test_redirect_requires_target_callback_execution_and_post_guard_continuation(self):
        p = self.proof()
        p['hook_coverage']['executed_callbacks']['cb']['executed_count'] = 0
        self.assertFalse(self.check(p))

        p = self.proof()
        p['hook_coverage']['executed_callbacks'] = {}
        self.assertFalse(self.check(p))

        p = self.proof()
        zend = self.zend()
        zend['events'] = [zend['events'][0]]
        self.assertFalse(verified_redirect(
            p, callback_id='cb', request_id='request', run_id='run', status=302,
            location='http://web/wp-admin/admin.php?page=forms',
            target='http://web/wp-admin/admin-ajax.php', zend=zend,
        ))

    def test_continuation_must_follow_nonce_in_same_callback(self):
        zend = self.zend()
        zend['events'].reverse()
        self.assertFalse(verified_redirect(
            self.proof(), callback_id='cb', request_id='request', run_id='run', status=302,
            location='http://web/wp-admin/admin.php?page=forms',
            target='http://web/wp-admin/admin-ajax.php', zend=zend,
        ))

    def test_nested_callback_execution_cannot_borrow_outer_proof(self):
        p = self.proof()
        p['hook_coverage']['executed_callbacks']['cb']['callback_id'] = 'outer'
        self.assertFalse(self.check(p))

    def test_guard_after_redirect_invalidates_proof(self):
        p = self.proof()
        p['guard_redirect_events'].append({'kind': 'guard', 'function': 'current_user_can', 'callback_id': 'cb'})
        self.assertFalse(self.check(p))

    def test_legacy_run_id_request_artifact_is_correlated(self):
        """Evidence correlation accepts legacy_run_id; the redirect gate must not reject the same artifact."""
        p = self.proof()
        p['legacy_run_id'] = p.pop('run_id')
        self.assertTrue(self.check(p))
        p['legacy_run_id'] = 'other'
        self.assertFalse(self.check(p))

    def test_php_callback_notation_is_normalized_for_zend_attribution(self):
        p = self.proof()
        p['hook_coverage']['executed_callbacks']['cb']['callback_repr'] = 'Fixture->callback'
        self.assertTrue(self.check(p))

    def test_zend_attribution_must_match_request_run_and_callback(self):
        for field in ('request_id', 'run_id'):
            with self.subTest(field=field):
                zend = self.zend()
                zend[field] = 'other'
                self.assertFalse(verified_redirect(
                    self.proof(), callback_id='cb', request_id='request', run_id='run',
                    status=302, location='http://web/wp-admin/admin.php?page=forms',
                    target='http://web/wp-admin/admin-ajax.php', zend=zend,
                ))
        zend = self.zend()
        zend['events'][1]['callback_context']['root_callback'] = 'Other::callback'
        self.assertFalse(verified_redirect(
            self.proof(), callback_id='cb', request_id='request', run_id='run', status=302,
            location='http://web/wp-admin/admin.php?page=forms',
            target='http://web/wp-admin/admin-ajax.php', zend=zend,
        ))
