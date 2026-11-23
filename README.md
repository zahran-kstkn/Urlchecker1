# Link Interceptor

A URL analysis demo. URL checks run locally in the browser and do not open or upload the checked URL. The extension can compare URLs against a bundled URLhaus feed snapshot; the snapshot must be downloaded and refreshed by a maintainer.

## Install as a browser extension

The extension uses the existing `index.html` as its toolbar popup. URL analysis, the bundled URLhaus snapshot, and access rules run in your browser; they do not contact the Python service or a reputation provider. It asks for permission to read links on websites so it can check clicked links. Exact-host rules stored in extension-local storage take priority over heuristics: **allow** proceeds, **warn** shows a prompt with the option to proceed or stay, and **block** stops that click and explains the rule. A rule applies only to its exact hostname (not subdomains). Explicit rules still apply if automatic in-page prompts are turned off. Without a matching rule, links scoring 15 or higher on the existing heuristic check show the warning. In WhatsApp Web, every clicked external web link shows the prompt by default, including links with no heuristic warnings, so you can review it before opening. The Guard intercepts clickable links, not plain text that merely contains a URL; WhatsApp must render the message text as an actual link. Scanning explains detected signals and common scam tactics; it does not follow redirects, and a bundled feed can become outdated, so no warning signs do not prove a site is safe. The **Paste** button only attempts to read the clipboard when clicked; the `clipboardRead` permission enables it.

These are browser link controls, not a network-wide firewall: they do not control other browsers, applications, or traffic that does not result from an intercepted link click. Rules are local to the browser extension and are not centrally administered. The popup's manual scanner reports a matching rule but does not open or block the manually entered URL.

### Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select this project folder (the one containing `manifest.json`).
4. Pin **Link Interceptor** from the Extensions menu for easy access. The first install asks for access to websites so it can check clicked links.

### Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on…**.
3. Firefox uses background scripts instead of the Chrome service worker. In PowerShell, create a Firefox-ready copy (the command bypasses execution policy for this script only; it does not change your system policy):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\build_firefox.ps1
   ```

4. In Firefox's file picker, select `firefox-build\manifest.json` and approve website access when prompted.
5. Make sure the extension is allowed to run on `web.whatsapp.com`, then refresh the WhatsApp Web tab.

Firefox temporary add-ons are removed when Firefox closes. For regular use, package the Firefox-ready folder as a ZIP and submit it to Mozilla Add-ons for signing; then install the signed XPI. Chrome continues to use the root `manifest.json`.

The WhatsApp Web link prompt does not work inside the WhatsApp mobile or desktop app. It checks URLs locally with simple heuristics, not a live threat database, and it does not follow redirects: a warning means there are signals to review, and no warning signals do not mean a site is safe.

### Try the local access rules

Open the extension popup and add exact hostnames (no `https://`, wildcard, path, or port), choose **allow**, **warn**, or **block**, and enter a reason. Saving another rule for the same hostname updates the existing rule. Rules are stored in the browser's extension-local storage. The standalone webpage uses that browser page's local storage instead; those page rules are not shared with the extension's click interceptor.

For a classroom demonstration, try adding these three rules:

| Hostname | Action | Reason |
| --- | --- | --- |
| `news.example.org` | Allow | Reserved example host for the allow demonstration |
| `paypa1-secure.test` | Warn | Reserved demo lookalike hostname |
| `account-verify.test` | Block | Reserved test hostname for demonstrating a block |

Click the matching sample links where available, and add a sample link for `account-verify.test` to a test page if needed. The `.test` names are reserved examples; these rules are for demonstration, not real threat intelligence. **Block** stops the intercepted browser link click only; entering a hostname manually or using another application is outside this extension's enforcement.

## Run

Install Python 3.10 or later. On Windows, open PowerShell in this folder and try the Python launcher:

```powershell
py -3 --version
py -3 server.py
```

If `py` is not recognized, install Python 3.10 or later from [python.org](https://www.python.org/downloads/windows/) and enable the Python launcher during setup. If `python` opens the Microsoft Store message, it is an App Execution Alias rather than the interpreter; either use `py -3` or turn off the `python.exe` and `python3.exe` aliases in **Settings > Apps > Advanced app settings > App execution aliases**.

In the current development environment, Python is available at `C:\msys64\mingw64\bin\python.exe`. You can use that interpreter directly if needed:

```powershell
$Python = "C:\msys64\mingw64\bin\python.exe"
& $Python --version
& $Python server.py
```

Open <http://127.0.0.1:8000/> in your browser. The SQLite database is created as `link_interceptor.sqlite3` the first time the server starts. Stop the service with Ctrl+C.

### School account and browser ID prototype

The Python-served webpage can register and sign in an account by emailing a six-digit one-time code to `@president.ac.id` or `@student.president.ac.id`. The first successful verification creates the account; the email suffix labels the account as lecturer or student. The browser also creates a random UUID as a per-browser identifier and registers it with the signed-in account. This is not a MAC address, device fingerprint, legal ID, or proof of device ownership. Email-code verification confirms access to that mailbox, not legal identity or an institution-approved sign-in; ask school IT for approval before using it beyond a class demo.

The account flow requires an SMTP service authorized to deliver to the school mailboxes. Configure these PowerShell environment variables before starting the server:

```powershell
$env:AUTH_SECRET = (py -3 -c "import secrets; print(secrets.token_urlsafe(48))")
$env:SMTP_HOST = "smtp.example.edu"
$env:SMTP_PORT = "587"
$env:SMTP_FROM = "link-interceptor@example.edu"
$env:SMTP_USER = "smtp-account"
$env:SMTP_PASSWORD = "provider-app-password"
py -3 server.py
```

If you are using the `$Python` interpreter variable above instead of the Python launcher, generate the secret with `& $Python -c "import secrets; print(secrets.token_urlsafe(48))"` and start the service with `& $Python server.py`.

`AUTH_SECRET`, `SMTP_HOST`, and `SMTP_FROM` are required; `SMTP_PORT` defaults to `587`. Set `SMTP_USER` and `SMTP_PASSWORD` together when the mail provider requires authentication. For an SSL SMTP endpoint, set `$env:SMTP_USE_SSL = "true"` and use the provider's SSL port. Keep secrets out of source control. The service hashes pending codes, expires them after 10 minutes, limits code attempts and requests, and uses an HttpOnly session cookie. Sessions last up to seven days. The browser ID remains in that browser's local storage after sign-out, and link URLs are not attached to the account or sent to the authentication endpoints.

The account UI requires the Python server; it is unavailable in the static GitHub Pages demo and the standalone extension popup. The extension's link checks continue to work independently. For a public service, deploy behind HTTPS and set `COOKIE_SECURE=true`; use school-approved email infrastructure and a persistent database if registrations must survive redeployments.

### Bundled URLhaus feed snapshot

The extension checks the exact URL against a local snapshot in `urlhaus-feed.js`; it does not call the URLhaus lookup API. The checked URL stays in the browser. The starter `urlhaus-feed.js` is empty until a maintainer generates it from a downloaded URLhaus feed. A match means the exact URL appears in that snapshot. URLhaus focuses on malware-distribution URLs rather than phishing-only reports, and a no-match does not mean a URL is safe.

To refresh the snapshot:

1. Sign in to the [URLhaus download/API page](https://urlhaus.abuse.ch/api/) and download a URLhaus CSV export or plain-text URL list using your Auth-Key. Do not put the key in this project, share it, or include it in a download URL that you commit.
2. Save the downloaded file locally, then run the converter from PowerShell in the project folder:

   ```powershell
   py -3 sync_urlhaus_feed.py "C:\path\to\your\download.csv"
   ```

   If `py` is unavailable, use your installed Python executable, for example:

   ```powershell
   & "C:\msys64\mingw64\bin\python.exe" sync_urlhaus_feed.py "C:\path\to\your\download.csv"
   ```

3. The converter replaces `urlhaus-feed.js` with unique valid HTTP/HTTPS URLs and a local generation timestamp. Reload the extension (and refresh open tabs) to use the updated snapshot. Repeat the download and conversion periodically; each extension update otherwise keeps using its bundled copy.

The converter accepts URLhaus CSV exports with a `url` column and plain-text files with one URL per line. It does not download the feed or need the Auth-Key itself. Before committing or redistributing a bundled feed, check the current [URLhaus API documentation](https://urlhaus.abuse.ch/api/) and [fair-use terms](https://abuse.ch/terms-of-use/#principles).

Run the backend tests with:

```powershell
py -3 -m unittest -v
```

Alternatively, run the tests with `& $Python -m unittest -v` if you set `$Python` to the interpreter path above.

## Data model

- `domains` stores normalized hostnames once.
- `reputation_entries` associates a domain with a confidence score and source.
- `threat_sources` describes where reputation entries came from.
- `brands` and `brand_domains` hold the official-domain lookup used for lookalike checks.

The built-in reputation rows use reserved `.test` domains and a `local-demo` source. They demonstrate database matching only; they are not real malicious-domain intelligence. The browser's URLhaus snapshot is separate from those sample rows; it is only as current as the last downloaded feed, and a low score is not proof that a URL is safe.

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

This static version does not use the Python API or SQLite database. Its URL checks run in the visitor's browser and include the bundled URLhaus snapshot, if populated. The built-in `.test` reputation entries are demonstrations only, not a live threat feed.

## Publish the Python service

1. Create a public GitHub repository and push these project files. Do not commit `link_interceptor.sqlite3`; it contains local database state and is ignored by Git.
2. On Render, create a **Web Service** connected to that GitHub repository.
3. Set the start command to `python server.py` and add the environment variable `HOST` with value `0.0.0.0`. Render supplies `PORT` automatically; the app reads it. (The `python` command is appropriate on Render; the Windows-specific launcher guidance above is for local development.)
4. Deploy, then open the public URL Render provides.

GitHub Pages only serves static files, so it cannot run this Python API. The page needs to be served by the Python web service for URL analysis to work. The default SQLite file lives on the service filesystem; that is fine for a demo, but some hosts reset that filesystem when a service restarts or redeploys. For persistent database edits, attach a persistent disk and set `DATABASE_PATH` to a file on its mount, such as `/var/data/link_interceptor.sqlite3`.

Before sharing broadly, review URLhaus's terms for distributing feed data, refresh the bundled snapshot, and review the service host's privacy and retention settings. This project is an educational heuristic demo, not a production anti-phishing verdict service.
