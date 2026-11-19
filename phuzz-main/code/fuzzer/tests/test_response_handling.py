import json
import sys
import unittest
from datetime import timedelta
from pathlib import Path

from requests import Response

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from core.candidate import Candidate


STATUSES = (200, 302, 400, 403, 404, 500)


def make_response(status, body):
    response = Response()
    response.status_code = status
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    response.url = "http://example.test/"
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Location"] = "/next"
    response.elapsed = timedelta(milliseconds=42)
    return response


class CandidateResponseTests(unittest.TestCase):
    def test_missing_response_serializes_safely(self):
        data = json.loads(str(Candidate()))
        self.assertEqual(data["response_body"], "")
        self.assertEqual(data["response.body.length"], 0)
        self.assertEqual(data["response.headers"], {})
        self.assertEqual(data["response.status.code"], 0)
        self.assertEqual(data["response.time"], 0)

    def test_existing_responses_keep_status_body_headers_and_time(self):
        for status in STATUSES:
            with self.subTest(status=status):
                candidate = Candidate()
                candidate.response = make_response(status, "response body")
                data = json.loads(str(candidate))
                self.assertEqual(data["response_body"], "response body")
                self.assertEqual(data["response.body.length"], 13)
                self.assertEqual(data["response.headers"], {
                    "Content-Type": "text/html; charset=utf-8", "Location": "/next"
                })
                self.assertEqual(data["response.status.code"], status)
                self.assertEqual(data["response.time"], 42)


class XSSResponseTests(unittest.TestCase):
    def test_missing_response_is_safe(self):
        from core.vulncheck import WebFuzzXSSVulnCheck, XSSVulnCheck

        candidate = Candidate()
        for checker in (WebFuzzXSSVulnCheck(), XSSVulnCheck()):
            with self.subTest(checker=checker.NAME):
                self.assertFalse(checker.check(candidate))
                self.assertEqual(candidate.vulns, [])

    def test_xss_criteria_apply_to_every_status(self):
        from core.vulncheck import WebFuzzXSSVulnCheck, XSSVulnCheck

        payload = "<script>alert(1)</script>"
        for status in STATUSES:
            with self.subTest(status=status, checker="XSS"):
                candidate = Candidate(fuzz_params={"query_params": {"q": payload}})
                candidate.response = make_response(status, payload)
                self.assertTrue(XSSVulnCheck().check(candidate))
                self.assertEqual(candidate.vulns, ["XSS"])

            with self.subTest(status=status, checker="WebFuzz"):
                candidate = Candidate()
                candidate.response = make_response(status, '<div title="0xdeadbeef"></div>')
                self.assertTrue(WebFuzzXSSVulnCheck().check(candidate))

    def test_status_alone_or_nonmatching_body_never_reports_xss(self):
        from core.vulncheck import WebFuzzXSSVulnCheck, XSSVulnCheck

        for status in STATUSES:
            for body in ("ordinary response", "0xdeadbeef"):
                with self.subTest(status=status, body=body):
                    candidate = Candidate(fuzz_params={"query_params": {"q": "<script>alert(1)</script>"}})
                    candidate.response = make_response(status, body)
                    self.assertFalse(XSSVulnCheck().check(candidate))
                    self.assertFalse(WebFuzzXSSVulnCheck().check(candidate))
                    self.assertEqual(candidate.vulns, [])


if __name__ == "__main__":
    unittest.main()
