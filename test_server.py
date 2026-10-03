import tempfile
import unittest
from pathlib import Path

import server


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
