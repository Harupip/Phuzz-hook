import json
import tempfile
import unittest
from pathlib import Path

from online_linked import probe_sender
from hook_energy.seed_generation.generated_config_runner import read_correlated_artifact_pair


class ReplayHTTPStatusTests(unittest.TestCase):
    def test_matching_callback_id_on_another_hook_is_not_target_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'target': 'http://web/test', 'methods': ['POST']}))
            requests, zend = root / 'requests', root / 'zend'
            requests.mkdir(); zend.mkdir()
            (requests / 'req.json').write_text(json.dumps({
                'request_id': 'req', 'run_id': 'run', 'hook_name': 'wp_ajax_test', 'callback_id': 'cb',
                'response': {'status_code': 200},
                'hook_coverage': {'executed_callbacks': {'cb': {'hook_name': 'wp_ajax_other'}}},
            }))
            (zend / 'req.json').write_text(json.dumps({'request_id': 'req', 'run_id': 'run'}))
            class Session:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def send(self, prepared, timeout, allow_redirects):
                    return type('Response', (), {'status_code': 200})()
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend,
            )
            self.assertFalse(result['callback_reached'])
            request_path = requests / 'req.json'
            request = json.loads(request_path.read_text())
            request['hook_coverage']['executed_callbacks'] = {
                'one': {'callback_id': 'cb'},
                'two': {'callback_id': 'cb', 'hook_name': 'wp_ajax_other'},
            }
            request_path.write_text(json.dumps(request))
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend,
            )
            self.assertFalse(result['callback_reached'])
            request['hook_coverage']['executed_callbacks'] = [{'callback_id': 'cb', 'hook_name': 'wp_ajax_other'}]
            request_path.write_text(json.dumps(request))
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend,
            )
            self.assertFalse(result['callback_reached'])

    def test_callback_list_can_confirm_target_without_top_level_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requests, zend = root / 'requests', root / 'zend'
            requests.mkdir(); zend.mkdir()
            (requests / 'req.json').write_text(json.dumps({
                'request_id': 'req', 'run_id': 'run', 'response': {'status_code': 403},
                'hook_coverage': {'executed_callbacks': [{'callback_id': 'cb', 'hook_name': 'wp_ajax_test'}]},
            }))
            (zend / 'req.json').write_text(json.dumps({'request_id': 'req', 'run_id': 'run'}))
            self.assertIsNotNone(read_correlated_artifact_pair(
                requests, zend, request_id='req', run_id='run',
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
            ))

    def test_correlated_redirect_with_only_unrelated_callbacks_is_not_a_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'target': 'http://web/test', 'methods': ['POST']}))
            requests, zend = root / 'requests', root / 'zend'
            requests.mkdir(); zend.mkdir()
            (requests / 'req.json').write_text(json.dumps({
                'request_id': 'req', 'run_id': 'run', 'response': {'status_code': 302},
                'hook_coverage': {'registered_callbacks': {'other': {'hook_name': 'wp_ajax_other'}}},
            }))
            (zend / 'req.json').write_text(json.dumps({'request_id': 'req', 'run_id': 'run'}))
            class Session:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def send(self, prepared, timeout, allow_redirects):
                    return type('Response', (), {'status_code': 302, 'headers': {'Location': '/wp-login.php'}})()
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend,
            )
            self.assertEqual(result['status'], 'request_completed')
            self.assertFalse(result['callback_reached'])
            self.assertEqual(result['response_location'], '/wp-login.php')
            request_path = requests / 'req.json'
            request = json.loads(request_path.read_text())
            request['hook_name'] = 'wp_ajax_test'
            request_path.write_text(json.dumps(request))
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend,
            )
            self.assertEqual(result['status'], 'request_completed')
            self.assertFalse(result['callback_reached'])

    def test_connection_error_keeps_already_correlated_callback_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'target': 'http://web/test', 'methods': ['POST']}))
            requests, zend = root / 'requests', root / 'zend'
            requests.mkdir(); zend.mkdir()
            (requests / 'req.json').write_text(json.dumps({
                'request_id': 'req', 'run_id': 'run', 'response': {'status_code': 500},
                'hook_coverage': {'executed_callbacks': {'cb': {'hook_name': 'wp_ajax_test'}}},
            }))
            (zend / 'req.json').write_text(json.dumps({'request_id': 'req', 'run_id': 'run'}))
            class Session:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def send(self, prepared, timeout, allow_redirects):
                    raise ConnectionError('closed after callback')
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend,
            )
            self.assertTrue(result['callback_reached'])
            self.assertEqual(result['request']['response']['status_code'], 500)
            self.assertIn('closed after callback', result['error'])

    def test_connection_error_without_artifacts_stays_an_http_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'target': 'http://web/test', 'methods': ['POST']}))
            class Session:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def send(self, prepared, timeout, allow_redirects):
                    raise ConnectionError('connection failed')
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=0.05,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=root / 'requests', zend_dir=root / 'zend',
            )
            self.assertEqual(result['status'], 'http_error')
            self.assertIn('connection failed', result['error'])
            self.assertNotIn('callback_reached', result)

    def test_late_connection_error_does_not_accept_artifacts_after_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'target': 'http://web/test', 'methods': ['POST']}))
            requests, zend = root / 'requests', root / 'zend'
            requests.mkdir(); zend.mkdir()
            (requests / 'req.json').write_text(json.dumps({
                'request_id': 'req', 'run_id': 'run', 'response': {'status_code': 500},
                'hook_coverage': {'executed_callbacks': {'cb': {'hook_name': 'wp_ajax_test'}}},
            }))
            (zend / 'req.json').write_text(json.dumps({'request_id': 'req', 'run_id': 'run'}))
            class Clock:
                now = 0
                def __call__(self): return self.now
            clock = Clock()
            class Session:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def send(self, prepared, timeout, allow_redirects):
                    clock.now = 2
                    raise ConnectionError('request timed out')
            result = probe_sender.send_and_wait(
                config, request_id='req', run_id='run', timeout_seconds=1,
                expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                session_factory=Session, request_dir=requests, zend_dir=zend, clock=clock,
            )
            self.assertEqual(result['status'], 'http_error')
            self.assertNotIn('callback_reached', result)

    def test_response_and_callback_evidence_are_independent(self):
        cases = [(200, True), (201, True), (204, True), (301, True), (302, True),
                 (302, False), (303, True), (304, False), (307, True), (308, True),
                 (400, True), (403, True), (403, False), (404, True), (404, False),
                 (500, True), (500, False)]
        for status, executed in cases:
            with self.subTest(status=status, executed=executed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config = root / 'config.json'
                config.write_text(json.dumps({'target': 'http://web/test', 'methods': ['POST']}))
                requests, zend = root / 'requests', root / 'zend'
                requests.mkdir()
                zend.mkdir()
                coverage = {} if not executed else {'registered_callbacks': {'cb': {'hook_name': 'wp_ajax_test'}}}
                if executed:
                    coverage['executed_callbacks'] = {'cb': {'hook_name': 'wp_ajax_test'}}
                (requests / 'req.json').write_text(json.dumps({
                    'request_id': 'req', 'run_id': 'run', 'response': {'status_code': status},
                    'hook_coverage': coverage,
                }))
                (zend / 'req.json').write_text(json.dumps({
                    'request_id': 'req', 'run_id': 'run', 'events': [{'path': ['observed']}],
                }))

                class Session:
                    def __enter__(self): return self
                    def __exit__(self, *args): return False
                    def send(self, prepared, timeout, allow_redirects):
                        assert allow_redirects is False
                        return type('Response', (), {'status_code': status, 'headers': {'Location': '/wp-login.php'}})()

                result = probe_sender.send_and_wait(
                    config, request_id='req', run_id='run', timeout_seconds=0.2,
                    expected={'hook_name': 'wp_ajax_test', 'callback_id': 'cb'},
                    session_factory=Session, request_dir=requests, zend_dir=zend,
                )
                self.assertEqual(result['status'], 'callback_reached' if executed else 'request_completed')
                self.assertEqual(result['response_status'], status)
                self.assertEqual(result['response_location'], '/wp-login.php')
                self.assertEqual(result['zend']['events'][0]['path'], ['observed'])

    def test_every_status_requires_matching_request_and_zend_ids(self):
        for status in (200, 201, 204, 301, 302, 303, 304, 307, 308, 400, 403, 404, 500):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                requests, zend = root / 'requests', root / 'zend'
                requests.mkdir()
                zend.mkdir()
                request = {'request_id': 'req', 'run_id': 'run', 'response': {'status_code': status}}
                artifact = {'request_id': 'req', 'run_id': 'run'}
                request_path, zend_path = requests / 'req.json', zend / 'req.json'
                request_path.write_text(json.dumps(request))
                def read():
                    return read_correlated_artifact_pair(requests, zend, request_id='req', run_id='run')
                self.assertIsNone(read())
                for field in ('request_id', 'run_id'):
                    request_path.write_text(json.dumps({**request, field: 'wrong'}))
                    zend_path.write_text(json.dumps(artifact))
                    self.assertIsNone(read())
                    request_path.write_text(json.dumps(request))
                    zend_path.write_text(json.dumps({**artifact, field: 'wrong'}))
                    self.assertIsNone(read())
                zend_path.write_text(json.dumps(artifact))
                self.assertIsNotNone(read())
