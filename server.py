import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from contextlib import closing
from email.message import EmailMessage
from http.cookies import CookieError, SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID
from urllib.parse import urlsplit


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "link_interceptor.sqlite3"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
MAX_REQUEST_BYTES = 8192
AUTH_CODE_SECONDS = 600
AUTH_SESSION_SECONDS = 60 * 60 * 24 * 7
AUTH_CODE_RESEND_SECONDS = 60
AUTH_CODE_MAX_ATTEMPTS = 5
AUTH_CODE_MAX_REQUESTS_PER_HOUR = 5
AUTH_SECRET = os.environ.get("AUTH_SECRET", "")
COOKIE_SECURE = os.environ.get(
    "COOKIE_SECURE",
    "false" if HOST in ("127.0.0.1", "localhost") else "true",
).lower() in ("1", "true", "yes")


def open_database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with closing(open_database()) as connection, connection:
        connection.executescript((BASE_DIR / "schema.sql").read_text(encoding="utf-8"))


def school_role_for_email(email):
    normalized = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@(?:student\.)?president\.ac\.id", normalized):
        return None
    return "student" if normalized.endswith("@student.president.ac.id") else "lecturer"


def auth_is_configured():
    has_smtp_auth = bool(os.environ.get("SMTP_USER")) == bool(os.environ.get("SMTP_PASSWORD"))
    return bool(
        len(AUTH_SECRET) >= 32
        and os.environ.get("SMTP_HOST")
        and os.environ.get("SMTP_FROM")
        and has_smtp_auth
    )


def code_digest(email, code):
    return hmac.new(AUTH_SECRET.encode("utf-8"), f"{email}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def valid_device_id(value):
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        identifier = UUID(value)
        return str(identifier) == value and identifier.version == 4
    except ValueError:
        return False


def send_verification_code(email, code):
    message = EmailMessage()
    message["Subject"] = "Your Link Interceptor sign-in code"
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = email
    message.set_content(
        f"Your Link Interceptor verification code is {code}.\n\n"
        "It expires in 10 minutes. If you did not request this code, you can ignore this message."
    )

    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    timeout = 10
    if os.environ.get("SMTP_USE_SSL", "").lower() in ("1", "true", "yes"):
        with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()) as client:
            if username:
                client.login(username, password)
            client.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as client:
            client.ehlo()
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
            if username:
                client.login(username, password)
            client.send_message(message)


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
        if self.path == "/api/auth/status":
            self.send_json(200, {"configured": auth_is_configured()})
            return
        if self.path == "/api/auth/me":
            self.send_json(200, {"user": self.current_user()})
            return
        if self.path == "/" or self.path.startswith("/?"):
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/auth/"):
            self.handle_auth_post()
            return
        if self.path != "/api/analyze":
            self.send_json(404, {"error": "Not found."})
            return
        try:
            payload = self.read_json_body()
            if payload is None:
                return
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

    def read_json_body(self, require_json=False):
        if require_json and self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Content-Type must be application/json."})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid request length."})
            return None
        if length < 1 or length > MAX_REQUEST_BYTES:
            self.send_json(413, {"error": "The request body must be under 8 KB."})
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "The request body must be valid JSON."})
            return None

    def same_origin_request(self):
        origin = self.headers.get("Origin")
        if not origin:
            return False
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return False
        return parsed.scheme in ("http", "https") and parsed.netloc.lower() == self.headers.get("Host", "").lower()

    def current_user(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        session_cookie = cookie.get("link_interceptor_session")
        if session_cookie is None:
            return None
        token_hash = hashlib.sha256(session_cookie.value.encode("utf-8")).hexdigest()
        now = int(time.time())
        with closing(open_database()) as connection:
            row = connection.execute(
                """SELECT users.user_id, users.email, users.role, user_devices.device_id
                   FROM user_sessions
                   JOIN users USING (user_id)
                   JOIN user_devices USING (user_id, device_id)
                   WHERE user_sessions.token_hash = ? AND user_sessions.expires_at > ?""",
                (token_hash, now),
            ).fetchone()
            connection.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (now,))
            connection.commit()
        return dict(row) if row else None

    def set_session_cookie(self, token):
        value = f"link_interceptor_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={AUTH_SESSION_SECONDS}"
        if COOKIE_SECURE:
            value += "; Secure"
        self.send_header("Set-Cookie", value)

    def clear_session_cookie(self):
        value = "link_interceptor_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        if COOKIE_SECURE:
            value += "; Secure"
        self.send_header("Set-Cookie", value)

    def handle_auth_post(self):
        if not self.same_origin_request():
            self.send_json(403, {"error": "This request must come from the Link Interceptor site."})
            return
        payload = self.read_json_body(require_json=True)
        if payload is None:
            return
        if not isinstance(payload, dict):
            self.send_json(400, {"error": "Invalid request."})
            return

        if self.path == "/api/auth/request-code":
            self.request_sign_in_code(payload)
        elif self.path == "/api/auth/verify-code":
            self.verify_sign_in_code(payload)
        elif self.path == "/api/auth/sign-out":
            self.sign_out()
        else:
            self.send_json(404, {"error": "Not found."})

    def request_sign_in_code(self, payload):
        email = payload.get("email", "")
        if not isinstance(email, str) or len(email) > 254 or not school_role_for_email(email):
            self.send_json(400, {"error": "Use your @president.ac.id or @student.president.ac.id school email."})
            return
        if not auth_is_configured():
            self.send_json(503, {"error": "School email verification is not configured on this server yet."})
            return

        email = email.strip().lower()
        now = int(time.time())
        with closing(open_database()) as connection:
            previous = connection.execute(
                """SELECT sent_at, request_count, window_started_at
                   FROM email_verification_codes WHERE email = ?""",
                (email,),
            ).fetchone()
            if previous and now - previous["sent_at"] < AUTH_CODE_RESEND_SECONDS:
                self.send_json(429, {"error": "Please wait a minute before requesting another code."})
                return
            same_window = previous and now - previous["window_started_at"] < 3600
            if same_window and previous["request_count"] >= AUTH_CODE_MAX_REQUESTS_PER_HOUR:
                self.send_json(429, {"error": "Too many code requests. Please try again in an hour."})
                return
            code = f"{secrets.randbelow(1_000_000):06d}"
            window_started_at = previous["window_started_at"] if same_window else now
            request_count = previous["request_count"] + 1 if same_window else 1
            connection.execute(
                """INSERT INTO email_verification_codes
                       (email, code_hash, expires_at, attempts, sent_at, request_count, window_started_at)
                   VALUES (?, ?, ?, 0, ?, ?, ?)
                   ON CONFLICT(email) DO UPDATE SET
                       code_hash = excluded.code_hash,
                       expires_at = excluded.expires_at,
                       attempts = 0,
                       sent_at = excluded.sent_at,
                       request_count = excluded.request_count,
                       window_started_at = excluded.window_started_at""",
                (email, code_digest(email, code), now + AUTH_CODE_SECONDS, now, request_count, window_started_at),
            )
            connection.commit()

        try:
            send_verification_code(email, code)
        except (OSError, smtplib.SMTPException, ValueError):
            with closing(open_database()) as connection:
                connection.execute(
                    """UPDATE email_verification_codes SET code_hash = '', expires_at = ?, attempts = ?
                       WHERE email = ? AND code_hash = ?""",
                    (now, AUTH_CODE_MAX_ATTEMPTS, email, code_digest(email, code)),
                )
                connection.commit()
            self.log_error("School email verification message could not be sent.")
            self.send_json(503, {"error": "The verification email could not be sent. Please try again later."})
            return
        self.send_json(200, {"message": "If the address is eligible, a sign-in code has been sent. Check your school inbox."})

    def verify_sign_in_code(self, payload):
        email = payload.get("email", "")
        code = payload.get("code", "")
        device_id = payload.get("deviceId", "")
        if (
            not isinstance(email, str)
            or len(email) > 254
            or not isinstance(code, str)
            or not re.fullmatch(r"\d{6}", code)
            or not school_role_for_email(email)
            or not valid_device_id(device_id)
        ):
            self.send_json(400, {"error": "Enter your eligible school email, six-digit code, and registered browser device ID."})
            return
        if not auth_is_configured():
            self.send_json(503, {"error": "School email verification is not configured on this server yet."})
            return

        email = email.strip().lower()
        now = int(time.time())
        with closing(open_database()) as connection, connection:
            row = connection.execute(
                "SELECT code_hash, expires_at, attempts FROM email_verification_codes WHERE email = ?",
                (email,),
            ).fetchone()
            if row is None or row["expires_at"] <= now or row["attempts"] >= AUTH_CODE_MAX_ATTEMPTS:
                if row is not None:
                    connection.execute(
                        """UPDATE email_verification_codes SET code_hash = '', expires_at = ?, attempts = ?
                           WHERE email = ?""",
                        (now, AUTH_CODE_MAX_ATTEMPTS, email),
                    )
                self.send_json(400, {"error": "That code is invalid or expired. Request a new one and try again."})
                return
            if not hmac.compare_digest(row["code_hash"], code_digest(email, code)):
                connection.execute(
                    "UPDATE email_verification_codes SET attempts = attempts + 1 WHERE email = ?",
                    (email,),
                )
                self.send_json(400, {"error": "That code is invalid or expired. Request a new one and try again."})
                return

            role = school_role_for_email(email)
            connection.execute(
                """INSERT INTO users (email, role, last_login_at) VALUES (?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(email) DO UPDATE SET role = excluded.role, last_login_at = CURRENT_TIMESTAMP""",
                (email, role),
            )
            user = dict(connection.execute(
                "SELECT user_id, email, role FROM users WHERE email = ?",
                (email,),
            ).fetchone())
            connection.execute(
                """INSERT INTO user_devices (user_id, device_id, last_login_at)
                   VALUES (?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(user_id, device_id) DO UPDATE SET last_login_at = CURRENT_TIMESTAMP""",
                (user["user_id"], device_id),
            )
            connection.execute(
                """UPDATE email_verification_codes SET code_hash = '', expires_at = ?, attempts = ?
                   WHERE email = ?""",
                (now, AUTH_CODE_MAX_ATTEMPTS, email),
            )
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            connection.execute(
                "INSERT INTO user_sessions (token_hash, user_id, device_id, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, user["user_id"], device_id, now + AUTH_SESSION_SECONDS),
            )
            connection.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (now,))

        body = json.dumps({"user": {**user, "device_id": device_id}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.set_session_cookie(token)
        self.end_headers()
        self.wfile.write(body)

    def sign_out(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            cookie = SimpleCookie()
        session_cookie = cookie.get("link_interceptor_session")
        if session_cookie:
            token_hash = hashlib.sha256(session_cookie.value.encode("utf-8")).hexdigest()
            with closing(open_database()) as connection, connection:
                connection.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
        body = json.dumps({"message": "Signed out."}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.clear_session_cookie()
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
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
