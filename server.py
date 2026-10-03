import ipaddress
import json
import os
import re
import sqlite3
from contextlib import closing
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "link_interceptor.sqlite3"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
MAX_REQUEST_BYTES = 8192


def open_database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with closing(open_database()) as connection, connection:
        connection.executescript((BASE_DIR / "schema.sql").read_text(encoding="utf-8"))


def edit_distance(left, right):
    row = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        diagonal = row[0]
        row[0] = index
        for other_index, right_char in enumerate(right, start=1):
            above = row[other_index]
            row[other_index] = min(
                row[other_index] + 1,
                row[other_index - 1] + 1,
                diagonal + (left_char != right_char),
            )
            diagonal = above
    return row[-1]


def normalized_label(label):
    translated = label.lower().translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "8": "b"}))
    return re.sub(r"[^a-z]", "", translated)


def analyze_url(raw_value):
    raw = raw_value.strip()
    candidate = raw if re.match(r"^[a-z][a-z\d+.-]*://", raw, re.IGNORECASE) else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        hostname = None

    if not hostname or parsed.scheme.lower() not in ("http", "https"):
        return None, "Enter a complete web address that starts with http:// or https://."

    hostname = hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "The hostname could not be decoded. Check the address and try again."

    labels = hostname.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9-]+", label) or label.startswith("-") or label.endswith("-") for label in labels):
        return None, "That hostname contains invalid characters. Check the address and try again."

    with closing(open_database()) as connection, connection:
        reputation_rows = connection.execute(
            """SELECT domains.hostname, reputation_entries.confidence, reputation_entries.note,
                      threat_sources.name AS source
               FROM reputation_entries
               JOIN domains USING (domain_id)
               JOIN threat_sources USING (source_id)"""
        ).fetchall()
        known_match = next(
            (entry for entry in reputation_rows if hostname == entry["hostname"] or hostname.endswith("." + entry["hostname"])),
            None,
        )
        brand_rows = connection.execute(
            """SELECT brands.name AS brand, domains.hostname AS hostname
               FROM brand_domains
               JOIN brands USING (brand_id)
               JOIN domains USING (domain_id)
               ORDER BY brands.name"""
        ).fetchall()

    official_hosts = {}
    for row in brand_rows:
        official_hosts.setdefault(row["brand"], []).append(row["hostname"])

    normalized_host = normalized_label(hostname)
    matching_brand = next(
        (
            brand for brand, domains in official_hosts.items()
            if brand in normalized_host and not any(hostname == domain or hostname.endswith("." + domain) for domain in domains)
        ),
        None,
    )
    host_labels = labels[:-1]
    near_brand = next(
        (
            brand for brand, domains in official_hosts.items()
            if not any(hostname == domain or hostname.endswith("." + domain) for domain in domains)
            and any(len(normalized_label(label)) >= 4 and edit_distance(normalized_label(label), brand) == 1 for label in host_labels)
        ),
        None,
    )
    suspected_brand = matching_brand or near_brand

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False

    subdomain_count = max(0, len(labels) - 2)
    encoded_host = any(label.startswith("xn--") for label in labels)
    suspicious_punctuation = "--" in hostname or "_" in hostname
    credentials = bool(parsed.username or parsed.password)
    long_url = len(raw) > 120

    checks = [
        {
            "name": "Reputation lookup",
            "detail": (
                f"This domain matches the local {known_match['source']} sample list. {known_match['note']}"
                if known_match else "No match in the local sample database. It is not connected to a live threat feed."
            ),
            "state": "bad" if known_match else "neutral",
            "weight": known_match["confidence"] if known_match else 0,
        },
        {
            "name": "Brand lookalike",
            "detail": (
                f"The hostname may be imitating {suspected_brand}. Verify its registered domain independently."
                if suspected_brand else "No common brand imitation was detected by these simple checks."
            ),
            "state": "bad" if suspected_brand else "good",
            "weight": 45 if suspected_brand else 0,
        },
        {
            "name": "Connection",
            "detail": "HTTPS is present, but encryption alone does not establish trust." if parsed.scheme.lower() == "https" else "This address uses HTTP, so the connection is not encrypted.",
            "state": "good" if parsed.scheme.lower() == "https" else "warn",
            "weight": 0 if parsed.scheme.lower() == "https" else 20,
        },
        {
            "name": "Host structure",
            "detail": "The hostname is an IP address rather than a familiar domain." if is_ip else f"{subdomain_count} subdomain{'s' if subdomain_count != 1 else ''}{'; unusually deep nesting can hide the actual domain.' if subdomain_count >= 3 else '.'}",
            "state": "warn" if is_ip or subdomain_count >= 3 else "good",
            "weight": 20 if is_ip else 15 if subdomain_count >= 3 else 0,
        },
        {
            "name": "Address format",
            "detail": "The URL contains user information before the host, a common deception tactic." if credentials else "The hostname uses punycode encoding; verify each character carefully." if encoded_host else "The hostname contains unusual punctuation." if suspicious_punctuation else "No user information or obvious hostname encoding was found.",
            "state": "warn" if credentials or encoded_host or suspicious_punctuation else "good",
            "weight": 30 if credentials else 15 if encoded_host or suspicious_punctuation else 0,
        },
        {
            "name": "URL length",
            "detail": f"This address is {len(raw)} characters long; long links can obscure their destination." if long_url else f"This address is {len(raw)} characters long.",
            "state": "warn" if long_url else "good",
            "weight": 10 if long_url else 0,
        },
    ]
    score = min(100, max(max(check["weight"] for check in checks), sum(check["weight"] for check in checks)))
    return {"hostname": hostname, "score": score, "checks": checks}, None


class RequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/api/health":
            self.send_json(200, {"status": "ok"})
            return
        if self.path == "/" or self.path.startswith("/?"):
            self.path = "/Main.html"
        super().do_GET()

    def do_POST(self):
        if self.path != "/api/analyze":
            self.send_json(404, {"error": "Not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > MAX_REQUEST_BYTES:
                self.send_json(413, {"error": "The request must contain a URL under 8 KB."})
                return
            payload = json.loads(self.rfile.read(length))
            raw_url = payload.get("url", "") if isinstance(payload, dict) else ""
            if not isinstance(raw_url, str) or not raw_url.strip():
                self.send_json(400, {"error": "Paste a URL to analyze."})
                return
            analysis, error = analyze_url(raw_url)
            if error:
                self.send_json(400, {"error": error})
                return
            self.send_json(200, analysis)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "The request body must be valid JSON."})

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), RequestHandler)
    display_host = "127.0.0.1" if HOST in ("0.0.0.0", "::") else HOST
    print(f"Link Interceptor is running at http://{display_host}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
