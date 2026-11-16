import unittest
from hashlib import sha256

from online_linked.redirect_gate import verified_redirect


REDIRECT_LOCATION = 'http://web/wp-admin/admin.php?page=forms'


def add_redirect_evidence(request, zend, *, callback_id, callback_repr, location=REDIRECT_LOCATION, status=302):
    location_hash = sha256(location.encode('utf-8')).hexdigest()
    request.update(
        response={'status_code': status, 'location_base': location.split('?', 1)[0],
                  'location_sha256': location_hash},
        hook_coverage={'executed_callbacks': {callback_id: {
            'callback_id': callback_id, 'callback_repr': callback_repr, 'executed_count': 1,
        }}},
        guard_redirect_events=[
            {'kind': 'guard', 'function': 'current_user_can', 'passed': True,
             'mode': 'override', 'callback_id': callback_id},
            {'kind': 'guard', 'function': 'wp_verify_nonce', 'passed': True,
             'mode': 'override', 'callback_id': callback_id},
            {'kind': 'redirect', 'function': 'wp_redirect', 'mode': 'observed',
             'callback_id': callback_id, 'status': status, 'location_sha256': location_hash},
        ],
    )
    zend['events'] = [
        {'source': source, 'path': [name], 'operation': 'read',
         'callback_context': {'attributed': True, 'root_callback': callback_repr}}
        for source, name in [('REQUEST', 'nonce'), ('GET', 'client_id')]
    ]


class RedirectGateTests(unittest.TestCase):
    def proof(self):
        request = {
            'request_id': 'request', 'run_id': 'run', 'auth_context': 'authenticated',
        }
        add_redirect_evidence(request, {}, callback_id='cb', callback_repr='Fixture::callback')
        return request

    def zend(self):
        return {
            'request_id': 'request', 'run_id': 'run',
            'events': [
                {'source': 'REQUEST', 'path': ['nonce'], 'operation': 'read',
                 'callback_context': {'attributed': True, 'root_callback': 'Fixture::callback'}},
                {'source': 'GET', 'path': ['client_id'], 'operation': 'read',
                 'callback_context': {'attributed': True, 'root_callback': 'Fixture::callback'}},
            ],
        }

    def check(self, payload, **kwargs):
        return verified_redirect(payload, callback_id='cb', request_id='request', run_id='run',
                                 status=302, location='http://web/wp-admin/admin.php?page=forms',
                                 target='http://web/wp-admin/admin-ajax.php', zend=self.zend(), **kwargs)

    def test_observed_override_checks_allow_same_request_redirect(self):
        self.assertTrue(self.check(self.proof()))

    def test_missing_failed_wrong_callback_and_uncorrelated_proof_stay_blocked(self):
        for change in ('missing', 'failed', 'wrong_callback', 'request', 'run', 'guest', 'status', 'location', 'order'):
            with self.subTest(change=change):
                p = self.proof()
                if change == 'missing': p['guard_redirect_events'].pop(1)
                elif change == 'failed': p['guard_redirect_events'][1]['passed'] = False
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

    def test_failed_guard_after_redirect_invalidates_proof(self):
        p = self.proof()
        p['guard_redirect_events'].append({
            'kind': 'guard', 'function': 'current_user_can', 'passed': False,
            'callback_id': 'cb', 'mode': 'override',
        })
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
