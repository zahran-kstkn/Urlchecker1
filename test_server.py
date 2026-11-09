import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server


class SchoolAccountTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_database = server.DATABASE
        self.original_auth_secret = server.AUTH_SECRET
        server.DATABASE = Path(self.temporary_directory.name) / "test.sqlite3"
        server.AUTH_SECRET = "test-only-auth-secret-for-unit-tests"
        self.smtp_environment = patch.dict(os.environ, {
            "SMTP_HOST": "smtp.example.test",
            "SMTP_FROM": "link-interceptor@example.test",
            "SMTP_USER": "",
            "SMTP_PASSWORD": "",
        })
        self.smtp_environment.start()
        server.initialize_database()
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.RequestHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        self.smtp_environment.stop()
        server.AUTH_SECRET = self.original_auth_secret
        server.DATABASE = self.original_database
        self.temporary_directory.cleanup()

    def post_json(self, path, payload, cookie=None, include_origin=True):
        headers = {"Content-Type": "application/json"}
        if include_origin:
            headers["Origin"] = self.origin
        if cookie:
            headers["Cookie"] = cookie
        request = Request(
            self.origin + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            return urlopen(request)
        except HTTPError as error:
            error.close()
            return error

    def test_student_email_registers_session_and_device(self):
        sent_codes = []
        device_id = "550e8400-e29b-41d4-a716-446655440000"
        with patch.object(server, "send_verification_code", side_effect=lambda email, code: sent_codes.append((email, code))):
            requested = self.post_json("/api/auth/request-code", {"email": "test@student.president.ac.id"})
            self.assertEqual(requested.status, 200)

            verified = self.post_json(
                "/api/auth/verify-code",
                {"email": sent_codes[0][0], "code": sent_codes[0][1], "deviceId": device_id},
            )
            result = json.loads(verified.read())
            self.assertEqual(result["user"]["role"], "student")
            self.assertEqual(result["user"]["device_id"], device_id)
            self.assertIn("HttpOnly", verified.headers["Set-Cookie"])
            cookie = verified.headers["Set-Cookie"].split(";", 1)[0]

            request = Request(self.origin + "/api/auth/me", headers={"Cookie": cookie})
            session = json.loads(urlopen(request).read())
            self.assertEqual(session["user"]["email"], "test@student.president.ac.id")
            self.assertEqual(session["user"]["device_id"], device_id)

            signed_out = self.post_json("/api/auth/sign-out", {}, cookie=cookie)
            self.assertEqual(signed_out.status, 200)
            request = Request(self.origin + "/api/auth/me")
            self.assertIsNone(json.loads(urlopen(request).read())["user"])

    def test_lecturer_school_email_is_recognized(self):
        self.assertEqual(server.school_role_for_email("lecturer@president.ac.id"), "lecturer")

    def test_non_school_email_and_invalid_device_id_are_rejected(self):
        response = self.post_json("/api/auth/request-code", {"email": "person@example.com"})
        self.assertEqual(response.status, 400)
        self.assertFalse(server.valid_device_id("not-a-device-id"))
        self.assertFalse(server.valid_device_id("550E8400-E29B-41D4-A716-446655440000"))
        self.assertFalse(server.valid_device_id("123e4567-e89b-12d3-a456-426614174000"))

    def test_verification_codes_are_single_use(self):
        sent_codes = []
        device_id = "550e8400-e29b-41d4-a716-446655440000"
        with patch.object(server, "send_verification_code", side_effect=lambda email, code: sent_codes.append((email, code))):
            self.post_json("/api/auth/request-code", {"email": "test@student.president.ac.id"})
            payload = {
                "email": sent_codes[0][0],
                "code": sent_codes[0][1],
                "deviceId": device_id,
            }
            self.assertEqual(self.post_json("/api/auth/verify-code", payload).status, 200)
            self.assertEqual(self.post_json("/api/auth/verify-code", payload).status, 400)

    def test_code_resend_is_rate_limited(self):
        with patch.object(server, "send_verification_code"):
            first = self.post_json("/api/auth/request-code", {"email": "test@student.president.ac.id"})
            second = self.post_json("/api/auth/request-code", {"email": "test@student.president.ac.id"})

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 429)

    def test_auth_post_requires_same_origin(self):
        response = self.post_json(
            "/api/auth/request-code",
            {"email": "person@student.president.ac.id"},
            include_origin=False,
        )
        self.assertEqual(response.status, 403)


class AnalyzeUrlTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_database = server.DATABASE
        server.DATABASE = Path(self.temporary_directory.name) / "test.sqlite3"
        server.initialize_database()

    def tearDown(self):
        server.DATABASE = self.original_database
        self.temporary_directory.cleanup()

    def test_reserved_demo_domain_is_found_in_database(self):
        result, error = server.analyze_url("http://paypa1-secure.test/login")

        self.assertIsNone(error)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["checks"][0]["state"], "bad")

    def test_brand_lookalike_is_flagged(self):
        result, error = server.analyze_url("https://secure-paypa1-login.test")

        self.assertIsNone(error)
        self.assertEqual(result["checks"][1]["state"], "bad")

    def test_https_sample_has_no_heuristic_warnings(self):
        result, error = server.analyze_url("https://news.example.org/story")

        self.assertIsNone(error)
        self.assertEqual(result["score"], 0)
        self.assertTrue(all(check["state"] in ("good", "neutral") for check in result["checks"]))

    def test_http_is_reported_as_unencrypted(self):
        result, error = server.analyze_url("http://news.example.org/story")

        self.assertIsNone(error)
        self.assertEqual(result["checks"][2]["state"], "warn")

    def test_incomplete_url_is_rejected(self):
        result, error = server.analyze_url("http://")

        self.assertIsNone(result)
        self.assertIsNotNone(error)

    def test_non_web_scheme_is_rejected(self):
        result, error = server.analyze_url("javascript:alert(1)")

        self.assertIsNone(result)
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
