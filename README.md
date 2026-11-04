# JS Extractor & Beautifier (v2)

Extracts, beautifies, and analyzes **all** JavaScript from a web page — built for recon and
front-end-heavy web application penetration testing.

It pulls inline `<script>` blocks, external `.js` files, Web Worker / Service Worker code, and
(optionally) chunks discovered via a headless browser, then beautifies everything and runs a
suite of static-analysis checks: endpoint discovery, parameter extraction for fuzzing, secret
scanning, framework fingerprinting, and known-CVE lookups.

> **Note:** live source→sink taint tracing (e.g. Burp Suite's DOM Invader) requires a human
> driving a real browser and cannot be automated from the CLI. This tool prepares everything
> DOM Invader needs — beautified JS, endpoints, and params — but the live-tracing step itself
> stays manual.

---

## Features

- Static extraction (`requests` + BeautifulSoup)
- Dynamic extraction via headless Chromium (Playwright) — `--dynamic`
- Follows JS imports/chunks referenced inside script files
- Parses source maps (`.js.map`) to recover original pre-bundle code — found via the
  `sourceMappingURL` comment, the `SourceMap`/`X-SourceMap` header, or by probing `<script>.map`
  (no extra dependency; uses the stdlib `json` parser)
- Extracts JS from Web Workers and Service Workers
- Framework detection (React, Vue, Angular, Next.js, Nuxt, Svelte, ...)
- Deep crawl via [katana](https://github.com/projectdiscovery/katana) to discover more JS across the site — `--katana`
- Historical URL collection via [gau](https://github.com/lc/gau) (Wayback/OTX/CommonCrawl/URLScan) to surface old/forgotten JS — `--gau`
- Alive-check gau results with [httpx](https://github.com/projectdiscovery/httpx) before extracting — `--httpx-probe`
- API endpoint discovery, including hidden/internal endpoint highlighting — `--endpoints`
- Parameter extraction for fuzzing wordlists — `--params`
- Secret/token/API-key pattern detection — `--secrets`
- Library version fingerprinting + CVE lookup via [OSV.dev](https://osv.dev) — `--cve`
- Optional integrations: `wappalyzer`, `retire.js`, `semgrep`, `LinkFinder`
- HTML analysis report generation — `--report`

---

## Requirements

- **Python 3.9+**
- Core Python dependencies (installed automatically): `requests`, `beautifulsoup4`, `jsbeautifier`

### Optional dependencies (only needed for specific flags)

| Flag                | Requires                                                                 |
|----------------------|---------------------------------------------------------------------------|
| `--dynamic`          | `playwright` (Python package) + Chromium browser binary                  |
| `--katana`           | [katana](https://github.com/projectdiscovery/katana) binary on `PATH`    |
| `--gau`              | [gau](https://github.com/lc/gau) binary on `PATH`                        |
| `--httpx-probe`      | [httpx](https://github.com/projectdiscovery/httpx) binary on `PATH` (ProjectDiscovery's HTTP toolkit — not the Python `httpx` library) |
| `--wappalyzer`       | `wappalyzer` CLI on `PATH`                                                |
| `--retire`           | `retire` (retire.js) CLI on `PATH`                                       |
| `--semgrep`          | `semgrep` CLI on `PATH`                                                  |
| `--linkfinder`       | `LinkFinder` (`linkfinder.py`) on `PATH`, or pass `--linkfinder-path`    |

> `install.sh` can install `katana`, `gau`, `httpx` (via `go install`), `wappalyzer`, `retire`
> (via `npm install -g`), and `semgrep` (via `pip`) for you interactively — it asks before
> installing each one. `LinkFinder` isn't packaged for any of those, so it stays manual (see
> the script's output for the clone command).

All optional external tools are detected at runtime (`shutil.which`); the Python package itself
**does not install them automatically** — if a tool isn't found, that specific analysis step is
skipped with a warning and the rest of the run continues normally. Use `install.sh` (below) to
install them interactively, or install each one manually with the commands in the table above.

---

## Installation

### Option 1 — Install as a CLI tool (recommended)

Clone the repo and install with pip. This registers a `js-extractor` command on your `PATH`.

```bash
git clone https://github.com/sobishirvanloo/js_extractor.git
cd js_extractor
pip install .
```

With optional dynamic-extraction support:

```bash
pip install ".[dynamic]"
playwright install chromium
```

### Option 2 — One-line installer script

```bash
git clone https://github.com/sobishirvanloo/js_extractor.git
cd js_extractor
chmod +x install.sh
./install.sh
```

The script installs the package, optionally sets up Playwright/Chromium, and then — if you say
yes — walks through installing each optional external tool (`katana`, `gau`, `httpx` via Go;
`wappalyzer`, `retire` via npm; `semgrep` via pip), asking before each one. Nothing external gets
installed without you confirming it.

### Option 3 — Run without installing

```bash
git clone https://github.com/sobishirvanloo/js_extractor.git
cd js_extractor
pip install -r requirements.txt
python3 js_extractor/cli.py <url> [options]
```

### Editable / development install

```bash
pip install -e .
```

---

## Usage

Once installed, the `js-extractor` command is available globally:

```bash
js-extractor <url> [options]
```

Or, without installing:

```bash
python3 js_extractor/cli.py <url> [options]
```

### Authentication

```bash
--cookie "name=value; name2=value2"
--jwt    "eyJ..."
--header "Key: Value"        # repeatable
--auth-scope host|domain     # where credentials are sent (default: exact target host only)
```

Credentials are never sent to third-party hosts (CDNs, analytics, cross-origin scripts,
redirect targets). Use `--auth-scope domain` when the app shares one session across
`app.` / `api.` / `auth.` subdomains.

### Network

```bash
--proxy URL                  # e.g. http://127.0.0.1:8080 (Burp/ZAP) or socks5://127.0.0.1:9050
--insecure, -k               # skip TLS verification (self-signed targets, intercepting proxies)
--ca-cert PATH               # verify TLS against a CA bundle instead (e.g. Burp's CA as PEM)
```

`--proxy` covers all traffic to the target: the static fetcher, `--dynamic`, katana and httpx.
gau, OSV.dev and semgrep only talk to public services and are not proxied. Behind Burp/ZAP,
add `--ca-cert` (export Burp's CA and convert it with `openssl x509 -inform der -in cacert.der -out burp.pem`)
or `--insecure`; `--dynamic` always needs `--insecure` there, since Chromium can't load a CA file.
SOCKS proxies need `pip install "requests[socks]"`.

### Scope

```bash
--scope any|domain|host      # hosts the tool may contact at all (default: any)
--include-host PATTERN       # extra allowed host for domain/host mode, glob OK (repeatable)
--exclude-host PATTERN       # never contact this host, glob OK, wins over everything (repeatable)
```

- `domain` = the target's registrable domain and all its subdomains; `host` = the exact target host.
- Out-of-scope scripts are listed in `out_of_scope.txt` instead of being fetched, and redirects
  that leave the scope are blocked.
- The scope also narrows katana (`-fs fqdn` for `host`), gau (no `--subs` for `host`, results
  filtered) and httpx (same-host redirects only). `--dynamic` aborts out-of-scope requests inside
  the browser. wappalyzer runs its own browser and does **not** honour `--scope` or `--proxy`.

### Extraction

```bash
--dynamic                    # Use headless browser (captures lazy-loaded JS)
--katana                     # Deep-crawl the site with katana to find more JS files
--katana-depth N              # Crawl depth for katana (default: 2)
--gau                         # Pull historical URLs via gau (Wayback/OTX/CommonCrawl/URLScan)
--gau-providers LIST          # Comma-separated gau providers, e.g. "wayback,otx" (default: all)
--httpx-probe                 # Probe --gau results with httpx, keep only URLs alive today
--no-inline                  # Skip inline <script> blocks
--no-external                # Skip external .js files
--no-workers                 # Skip Web Workers / Service Workers
--no-sourcemaps              # Skip source map recovery (incl. probing <script>.map)
--no-imports                 # Skip following import/require chains
```

### Analysis

```bash
--endpoints                  # Extract API endpoints from all JS
--params                     # Extract parameters for fuzzing
--secrets                    # Scan for leaked keys/tokens/passwords
--cve                        # Fingerprint library versions & check OSV.dev for known CVEs
--wappalyzer                 # Run wappalyzer CLI for tech-stack fingerprinting
--retire                     # Run retire.js against downloaded JS (local CVE signatures)
--semgrep                    # Run semgrep static analysis (default: p/xss, p/javascript)
--semgrep-config RULESET     # Add/override semgrep ruleset (repeatable)
--linkfinder                 # Run LinkFinder against downloaded JS for endpoint extraction
--linkfinder-path PATH       # Path to linkfinder.py if not on PATH
--all-analysis                # Enable all analysis flags above
--tool-timeout SECONDS       # Timeout per external tool run (partial katana/gau/httpx output is kept)
```

### Output

```bash
--output-dir  ./js_output    # Output directory (default: ./js_output)
--merge                      # Combine all scripts into one file
--report                     # Generate HTML analysis report
```

### Examples

Through Burp, staying strictly on the target's domain:

```bash
js-extractor https://app.target.com \
  --proxy http://127.0.0.1:8080 --ca-cert burp.pem \
  --scope domain --exclude-host "*.google-analytics.com" \
  --cookie "session=abc123" --auth-scope domain \
  --endpoints --secrets --report
```

Basic static extraction:

```bash
js-extractor https://target.com
```

Full recon pass — dynamic extraction, deep crawl, historical URLs (alive-checked), all analysis, HTML report:

```bash
js-extractor https://target.com \
  --dynamic --katana --gau --httpx-probe --all-analysis --merge --report \
  --output-dir ./target_js
```

Historical JS only, without probing (faster, noisier):

```bash
js-extractor https://target.com --gau --gau-providers wayback,otx
```

Authenticated scan behind a login:

```bash
js-extractor https://target.com/dashboard \
  --cookie "session=abc123" \
  --header "X-Custom-Header: value" \
  --endpoints --secrets --cve
```

---

## Output structure

```
js_output/
├── external/                # Downloaded + beautified external .js files
├── inline/                  # Beautified inline <script> blocks
├── sourcemap_recovered/     # Original sources, one folder per bundle (+ _sources.txt index)
├── ALL_SCRIPTS_MERGED.js    # (with --merge)
├── endpoints.txt            # (with --endpoints)
├── endpoints_hidden.txt     # (with --endpoints)
├── gau_all.txt              # (with --gau, no probe)
├── gau_alive.txt            # (with --gau --httpx-probe) — "status_code  url" per line
├── params_wordlist.txt      # (with --params)
├── out_of_scope.txt         # (with --scope/--exclude-host) script URLs skipped as out of scope
├── secrets.json             # (with --secrets) unmasked values + every file:line location
├── cve_report.txt           # (with --cve)
├── retire_report.txt        # (with --retire)
├── semgrep_report.txt       # (with --semgrep)
├── linkfinder_endpoints.txt # (with --linkfinder)
└── report.html              # (with --report)
```

---

## Disclaimer

This tool is intended for authorized security testing and research only. Only run it against
targets you own or have explicit written permission to test. The authors are not responsible for
any misuse.

## License

MIT
