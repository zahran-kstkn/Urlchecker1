import argparse
import csv
import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from urllib.parse import urlsplit


def valid_web_url(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname) and not parsed.username and not parsed.password
    except ValueError:
        return False


def extract_urls(feed_text):
    lines = [line.strip() for line in feed_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return []

    first_row = next(csv.reader([lines[0]]))
    headers = [field.strip().lower() for field in first_row]
    if "url" in headers:
        urls = []
        for row in csv.DictReader(StringIO("\n".join(lines))):
            url = row.get("url", "").strip()
            if valid_web_url(url):
                urls.append(url)
    elif len(first_row) >= 3 and valid_web_url(first_row[2].strip()):
        urls = []
        for row in csv.reader(lines):
            if len(row) >= 3:
                url = row[2].strip()
                if valid_web_url(url):
                    urls.append(url)
    else:
        urls = [line for line in lines if valid_web_url(line)]

    return sorted(set(urls))


def render_feed(urls, generated_at):
    feed = {"generatedAt": generated_at, "urls": urls}
    return (
        "globalThis.LinkInterceptorURLhausFeed = "
        + json.dumps(feed, ensure_ascii=True, separators=(",", ":"))
        + ";\n"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Convert a downloaded URLhaus CSV or URL list into the extension's local feed."
    )
    parser.add_argument("download", type=Path, help="Downloaded URLhaus CSV or text URL list")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "urlhaus-feed.js",
        help="Generated JavaScript feed path (defaults to urlhaus-feed.js next to this script)",
    )
    arguments = parser.parse_args()

    urls = extract_urls(arguments.download.read_text(encoding="utf-8-sig"))
    if not urls:
        parser.error("The input contains no valid HTTP or HTTPS URLs; the existing feed was not changed.")

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    arguments.output.write_text(render_feed(urls, generated_at), encoding="utf-8")
    print(f"Wrote {len(urls):,} unique URLhaus URLs to {arguments.output}")


if __name__ == "__main__":
    main()
