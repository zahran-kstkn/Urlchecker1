# Link Interceptor

A URL analysis demo. The service analyzes submitted URLs but never opens them or sends them to an external reputation provider. When hosted publicly, submitted URLs are sent to the server hosting this app.

## Run

Install Python 3.10 or later, then open PowerShell in this folder and run:

```powershell
python server.py
```

Open <http://127.0.0.1:8000/> in your browser. The SQLite database is created as `link_interceptor.sqlite3` the first time the server starts. Stop the service with Ctrl+C.

Run the backend tests with:

```powershell
python -m unittest -v
```

## Data model

- `domains` stores normalized hostnames once.
- `reputation_entries` associates a domain with a confidence score and source.
- `threat_sources` describes where reputation entries came from.
- `brands` and `brand_domains` hold the official-domain lookup used for lookalike checks.

The built-in reputation rows use reserved `.test` domains and a `local-demo` source. They demonstrate database matching only; they are not real malicious-domain intelligence. The application does not subscribe to or query a live threat feed, and a low score is not proof that a URL is safe.

To add a known-bad hostname, add the normalized domain and its reputation record in a SQLite client:

```sql
INSERT OR IGNORE INTO threat_sources (name, description)
VALUES ('curated-feed', 'Domains reviewed against your chosen trusted source.');

INSERT OR IGNORE INTO domains (hostname) VALUES ('suspicious.example');

INSERT OR IGNORE INTO reputation_entries (domain_id, source_id, confidence, note)
SELECT domains.domain_id, threat_sources.source_id, 100, 'Verified by your trusted source.'
FROM domains
JOIN threat_sources ON threat_sources.name = 'curated-feed'
WHERE domains.hostname = 'suspicious.example';
```

For real deployments, create a separate `threat_sources` row for each feed and record provenance and review dates. Keep the feed current and avoid treating an unverified report as confirmed malicious activity.

## GitHub Pages demo

`index.html` is a static, browser-only demo that works on GitHub Pages. In your GitHub repository, open **Settings > Pages**, choose **Deploy from a branch**, select `main` and the `/ (root)` folder, then save. GitHub will show the public URL after deployment.

This static version does not use the Python API or SQLite database. Its URL checks run in the visitor's browser, and its built-in `.test` reputation entries are demonstrations only, not a live threat feed.

## Publish the Python service

1. Create a public GitHub repository and push these project files. Do not commit `link_interceptor.sqlite3`; it contains local database state and is ignored by Git.
2. On Render, create a **Web Service** connected to that GitHub repository.
3. Set the start command to `python server.py` and add the environment variable `HOST` with value `0.0.0.0`. Render supplies `PORT` automatically; the app reads it.
4. Deploy, then open the public URL Render provides.

GitHub Pages only serves static files, so it cannot run this Python API. The page needs to be served by the Python web service for URL analysis to work. The default SQLite file lives on the service filesystem; that is fine for a demo, but some hosts reset that filesystem when a service restarts or redeploys. For persistent database edits, attach a persistent disk and set `DATABASE_PATH` to a file on its mount, such as `/var/data/link_interceptor.sqlite3`.

Before sharing broadly, replace the `.test` demo entries with a maintained, trusted reputation source, and review the service host's privacy and retention settings. This project is an educational heuristic demo, not a production anti-phishing verdict service.
