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
- Follows JS imports/chunks referenced inside script files, plus `<link rel="modulepreload">` / `preload as=script`
- **Lazy chunk discovery**: downloads the route-split chunks an SPA only loads on navigation, which no
  `<script>` tag references:
  - webpack 4/5 (CRA, Angular CLI, Vue CLI, Next.js): rebuilds chunk URLs from the runtime's chunk-URL
    function, its `{id: hash}` maps and public path, including runtimes inlined into the HTML
  - Next.js: finds `_buildManifest.js` from the `buildId` and recovers every page route (`routes.txt`)
  - Vite: preload dependency lists and a publicly deployed `.vite/manifest.json`
- Parses source maps (`.js.map`) to recover original pre-bundle code — found via the
  `sourceMappingURL` comment, the `SourceMap`/`X-SourceMap` header, or by probing `<script>.map`
  (no extra dependency; uses the stdlib `json` parser)
- Extracts JS from Web Workers and Service Workers
- Framework detection (React, Vue, Angular, Next.js, Nuxt, Svelte, ...)
- Deep crawl via [katana](https://github.com/projectdiscovery/katana) to discover more JS across the site — `--katana`
- Historical URL collection via [gau](https://github.com/lc/gau) (Wayback/OTX/CommonCrawl/URLScan) to surface old/forgotten JS — `--gau`
- Alive-check gau results with [httpx](https://github.com/projectdiscovery/httpx) before extracting — `--httpx-probe`
- **Wayback recovery** — `--wayback`: scripts that are gone today (404/410, an HTML page instead of JS, or
  gau URLs httpx reports dead) are fetched from their newest Wayback Machine snapshot, together with their
  archived source maps, and analysed with everything else. Old bundles often still reference endpoints the
  current front end dropped but the backend still serves
- API endpoint discovery — `--endpoints`: each endpoint comes with its HTTP method when the code
  shows it (`fetch` options, `axios.post`, `xhr.open("PATCH", …)`, `$.ajax({type})`, Angular
  `HttpClient`) and the file:line it came from; "hidden/internal" is flagged on whole path tokens
  (`/internal/`, `adminPanel`, `debug`, `actuator`…), so `latest` or `devices` no longer match
- Parameter extraction for fuzzing wordlists — `--params`: only names that reach a request —
  query strings, `URLSearchParams`/`FormData`, request bodies (`JSON.stringify({...})`, `body:`/`data:`/
  `params:`/`variables:`, `axios.post(url, {...})`), route params (`/:id`), GraphQL variables and form fields
- Secret detection — `--secrets`: ~35 formats (AWS, GitHub, GitLab, Slack, Stripe, Twilio, SendGrid,
  Mailgun, Mailchimp, npm, PyPI, Shopify, Telegram, Square, OpenAI, Anthropic, Azure, Discord/Slack
  webhooks, private keys, credentials in URLs, JWTs, …) with a severity: **high** (grants access),
  **medium** (generic `apiKey`/`secret`/`password` values, after entropy and placeholder filtering),
  **low** (public by design: Google browser keys, Stripe/Mapbox publishable keys, Sentry DSNs). JWTs are
  decoded: a Supabase `service_role` key is high, an `anon` key low. `--fail-on secrets` ignores low.
- **DOM XSS taint analysis** — `--dom` (`js_extractor/dom.py`): a static map of where untrusted data
  can reach a dangerous sink, for triage and for driving manual testing (e.g. DOM Invader). Not proof
  of exploitability.
  - **Sources**: `location.*`, `document.URL`/`referrer`/`cookie`, `window.name`, `URLSearchParams(location)`,
    `history.state`, web storage, postMessage data, and framework routing — Vue `$route`, Next.js/React
    Router (`router.query`, `useSearchParams`, `useParams`, `useLocation`), Angular `ActivatedRoute`.
  - **Sinks** by kind — html (`innerHTML`, `document.write`, `insertAdjacentHTML`, `setHTMLUnsafe`, React
    `dangerouslySetInnerHTML`, Vue `v-html`, jQuery `.html()`/`$()`/`.append()`…), code (`eval`,
    `Function`, string/tainted `setTimeout`), script-url (`<script>.src`, `new Worker`, `import()`),
    navigation (`location`, `window.open`, `<iframe>.src`, `<a>.href`), storage/cookie writes, Angular
    `bypassSecurityTrust*`.
  - **Taint tracking** through variable chains (incl. destructuring), killed by clean reassignment and
    bounded in distance so minified name reuse doesn't create false flows; plus one level of
    **function calls** (a function whose parameter reaches a sink, called with tainted data).
  - **Downgrades instead of hiding**: sanitizers (`DOMPurify.sanitize`, `encodeURIComponent`, escapers,
    numeric casts), constant URL prefixes (same-origin path → low; `//` + host → open redirect),
    stored sources (storage/cookies) and message handlers with a strict origin check.
  - **postMessage handlers** (inline, arrow, destructured or named) classified by origin check: none
    (high), weak `indexOf`/`includes`/regex-style (medium), strict (not reported).
  - Each finding has a severity, a confidence and a **trace** — e.g.
    `location (L10) → a1 (L10) → b1 (L11) → c1 (L12) → innerHTML (L13)`. `dom_sources.json` lists
    every source read.
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

### Performance

```bash
--threads N, -t N            # parallel script downloads (default: 5)
--rate-limit RPS             # max requests/second across all threads, 0 = unlimited (default: 10)
--max-files N                # download at most N external scripts, 0 = unlimited (default)
--max-size MB                # skip any response larger than this, 0 = unlimited (default: 30)
```

Output is identical from run to run regardless of thread timing (files are numbered in discovery
order). Scripts that turn out to be HTML pages (soft 404s, login redirects, WAF pages) are skipped.

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
--wayback                     # Fetch archived copies of scripts that are gone today
--wayback-max N               # Look up at most N dead scripts (default: 50)
--no-inline                  # Skip inline <script> blocks
--no-external                # Skip external .js files
--no-workers                 # Skip Web Workers / Service Workers
--no-sourcemaps              # Skip source map recovery (incl. probing <script>.map)
--no-imports                 # Skip following import/require chains
--no-chunks                  # Skip lazy-chunk discovery (webpack/Next.js/Vite)
```

### Analysis

```bash
--endpoints                  # Extract API endpoints from all JS
--params                     # Extract parameters for fuzzing
--secrets                    # Scan for leaked keys/tokens/passwords
--dom                        # Map DOM XSS sinks/sources and postMessage issues
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
--json                       # Print results.json to stdout (progress goes to stderr)
--fail-on LIST               # Exit 3 if found: secrets,cves,hidden-endpoints,retire,semgrep,dom (high)
```

`results.json` is always written. It holds every finding (secrets unmasked), the file list, the
out-of-scope and skipped URLs, and run stats. Exit codes: `0` ok, `1` target unreachable,
`2` bad arguments, `3` a `--fail-on` category matched. `--fail-on X` turns on the analysis that
produces `X`.

```bash
# CI gate: fail the build if the deployed JS leaks a secret
js-extractor https://staging.example.com --fail-on secrets --json > js-results.json

# pipe endpoints into other tools
js-extractor https://example.com --endpoints --json | jq -r '.endpoints[]' | sort -u
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
├── archived/                # (with --wayback) Wayback copies of scripts that are gone today
├── sourcemap_recovered/     # Original sources, one folder per bundle (+ _sources.txt index)
├── ALL_SCRIPTS_MERGED.js    # (with --merge)
├── endpoints.txt            # (with --endpoints)
├── endpoints_hidden.txt     # (with --endpoints)
├── gau_all.txt              # (with --gau, no probe)
├── gau_alive.txt            # (with --gau --httpx-probe) — "status_code  url" per line
├── params_wordlist.txt      # (with --params)
├── results.json             # always: all findings + stats, machine-readable
├── routes.txt               # (Next.js) client-side routes from _buildManifest.js
├── out_of_scope.txt         # (with --scope/--exclude-host) script URLs skipped as out of scope
├── dom_sinks.json           # (with --dom) findings with severity, confidence, trace, file:line
├── dom_sources.json         # (with --dom) every place a DOM source is read
├── secrets.json             # (with --secrets) unmasked values + every file:line location
├── cve_report.txt           # (with --cve)
├── retire_report.txt        # (with --retire)
├── semgrep_report.txt       # (with --semgrep)
├── linkfinder_endpoints.txt # (with --linkfinder)
└── report.html              # (with --report)
```

---

## Project layout

```
js_extractor/
├── cli.py               # arguments + orchestration (main / _run); re-exports the public API
├── net.py               # fetch(), Scope, ScopedAuth, RateLimiter, sessions, proxy/TLS
├── ui.py · output.py    # colours · beautify, save_js, results.json
├── jsparse.py           # linear-time JS scanning helpers (no parser)
├── report.py            # HTML report
├── discovery/           # finding the JavaScript
│   ├── html.py          #   <script>, preload/modulepreload, <base href>
│   ├── dynamic.py       #   headless Chromium (Playwright)
│   ├── imports.py       #   import/require chains, Web/Service Workers
│   ├── chunks.py        #   webpack runtimes, Next.js/Vite manifests
│   ├── sourcemaps.py    #   source map discovery and safe recovery
│   └── wayback.py       #   archived copies of scripts that are gone
├── analyzers/           # analysing it
│   ├── dom.py           #   DOM XSS taint analysis
│   ├── endpoints.py · params.py · secrets.py
│   └── frameworks.py · versions.py (+ OSV.dev CVEs)
└── integrations/
    └── tools.py         # katana, gau, httpx, wappalyzer, retire.js, semgrep, LinkFinder
```

## Testing

```bash
pip install -e ".[dev]"
pytest                          # all suites (~40s)
pytest -k chunks                # a single suite
python tests/suite_chunks.py    # run one suite directly, with full output
```

The suites in `tests/suite_*.py` are end-to-end: they start local HTTP/HTTPS servers (simulated
CRA, Next.js and Vite apps, a fake forward proxy, a self-signed TLS server) and stand-in versions
of katana, gau, httpx, retire, semgrep and LinkFinder, then run the real CLI against them. Each
suite runs in its own process because some patch module globals. `openssl` must be on `PATH`
(it generates the test certificate). CI runs on every push and pull request
(`.github/workflows/tests.yml`, Python 3.9 and 3.12).

## Disclaimer

This tool is intended for authorized security testing and research only. Only run it against
targets you own or have explicit written permission to test. The authors are not responsible for
any misuse.

## License

MIT
