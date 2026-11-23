import unittest

from sync_urlhaus_feed import extract_urls, render_feed


class URLhausFeedTests(unittest.TestCase):
    def test_extracts_unique_urls_from_urlhaus_csv_and_ignores_invalid_entries(self):
        source = """# URLhaus export
id,dateadded,url,url_status
1,2026-11-23 10:00:00,https://malware.example/payload,online
2,2026-11-23 10:01:00,https://malware.example/payload,offline
3,2026-11-23 10:02:00,javascript:alert(1),online
4,2026-11-23 10:03:00,https://user:pass@example.test/,online
"""

        self.assertEqual(extract_urls(source), ["https://malware.example/payload"])

    def test_extracts_urls_from_plain_text_download(self):
        source = "# URLhaus\nhttps://malware.example/a\ninvalid line\nhttp://malware.example/b\n"

        self.assertEqual(
            extract_urls(source),
            ["http://malware.example/b", "https://malware.example/a"],
        )

    def test_extracts_urls_from_headerless_urlhaus_csv(self):
        source = """# URLhaus CSV export
"4074572","2026-11-23 07:17:06","https://malware.example/payload.zip","online","malware_download"
"4074571","2026-11-23 07:08:12","https://malware.example/payload.zip","offline","malware_download"
"""

        self.assertEqual(
            extract_urls(source),
            ["https://malware.example/payload.zip"],
        )

    def test_rendered_feed_is_safe_javascript_json(self):
        source = render_feed(["https://malware.example/?q=1"], "2026-11-23T00:00:00Z")

        self.assertIn('globalThis.LinkInterceptorURLhausFeed = ', source)
        self.assertIn('"generatedAt":"2026-11-23T00:00:00Z"', source)
        self.assertIn('"urls":["https://malware.example/?q=1"]', source)


if __name__ == "__main__":
    unittest.main()
