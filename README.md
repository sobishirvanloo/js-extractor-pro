# jxray — deep JavaScript recon

**jxray** x-rays a web app's JavaScript: it extracts, beautifies, and analyzes **all** of it —
built for recon and front-end-heavy web application penetration testing.

It pulls inline `<script>` blocks, external `.js` files, Web Worker / Service Worker code, lazy
webpack/Vite/Next.js chunks, source-map originals, and (optionally) code discovered via a headless
browser, then beautifies everything and runs a suite of static-analysis checks: endpoint discovery,
parameter extraction for fuzzing, secret scanning, framework fingerprinting, known-CVE lookups,
DOM-XSS taint analysis, GraphQL operation/endpoint extraction, embedded-config and feature-flag
mining, source intelligence with an npm dependency-confusion check, and replay-ready output
(OpenAPI + curl + ffuf). It runs against a live URL, a list of URLs, or JS files already on disk,
and ships as a Docker image so the only thing you install is Docker.

> **Note:** live source→sink taint tracing (e.g. Burp Suite's DOM Invader) requires a human
> driving a real browser and cannot be automated from the CLI. This tool prepares everything
> DOM Invader needs — beautified JS, endpoints, and params — but the live-tracing step itself
> stays manual.

> ⚠️ **Authorized use only.** Run this against targets you own or have explicit written
> permission to test (your own lab, a CTF, a bug-bounty scope). See [Disclaimer](#disclaimer).

---

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Tutorial — your first scan, step by step](#tutorial--your-first-scan-step-by-step)
- [Output structure](#output-structure)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Quick start

The fastest path, with nothing to install but Docker:

```bash
git clone https://github.com/sobishirvanloo/js-extractor-pro.git
cd js-extractor-pro
docker build -t jxray .

# scan a target you're allowed to test; results land in ./out on your machine
docker run --rm -v "$PWD/out:/work" jxray https://example.com --all-analysis --report
open out/report.html     # macOS; use xdg-open on Linux, start on Windows
```

Prefer Python? With Python 3.9+:

```bash
pip install .
jxray https://example.com --all-analysis --report --output-dir ./out
```

New here? Jump to the [step-by-step tutorial](#tutorial--your-first-scan-step-by-step).

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
- **DOM XSS taint analysis** — `--dom` (`jxray/dom.py`): a static map of where untrusted data
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
- Library version fingerprinting + CVE lookup via [OSV.dev](https://osv.dev) — `--cve`: versions
  come from both banner comments and versioned filenames (`jquery-3.5.1.min.js`); all libraries are
  resolved in a single batched OSV query, and each CVE is given a numeric CVSS base score and a
  NONE/LOW/MEDIUM/HIGH/CRITICAL band so findings sort and feed `--fail-on cves`
- **GraphQL recon** — `--graphql`: operations (query/mutation/subscription) with their root fields,
  fragments, and client transport endpoints (Apollo/urql `uri:`, `/graphql` paths), pulled from
  bundles and `gql` template literals. `--graphql-introspect` additionally sends an introspection
  query to each in-scope endpoint and records any schema that answers (active; live targets only)
- **Embedded config** — `--config`: config objects (`__CONFIG__`, `__NEXT_DATA__`, Firebase, …),
  boolean feature flags, internal/non-routable hosts and cloud-metadata IPs, cloud storage/service
  references (S3/GCS/Azure/Firebase/API Gateway) and `process.env` variable names
- **Replay-ready output** — `--replay`: turns the endpoint list into an OpenAPI 3.0 spec
  (`openapi.json`), ready-to-run `curl` commands carrying your auth, and `ffuf` parameter-fuzzing lines
- **Source intelligence** — `--source-intel`: from recovered first-party code, the import/package
  list, the original project tree, developer emails and TODO/FIXME notes. `--dep-confusion` then
  checks each package against the public npm registry and flags unpublished (claimable) names —
  especially scoped `@org/*` — as dependency-confusion candidates
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

Clone the repo and install with pip. This registers a `jxray` command on your `PATH`.

```bash
git clone https://github.com/sobishirvanloo/jxray.git
cd jxray
pip install .
```

With optional dynamic-extraction support:

```bash
pip install ".[dynamic]"
playwright install chromium
```

### Option 2 — One-line installer script

```bash
git clone https://github.com/sobishirvanloo/jxray.git
cd jxray
chmod +x install.sh
./install.sh
```

The script installs the package, optionally sets up Playwright/Chromium, and then — if you say
yes — walks through installing each optional external tool (`katana`, `gau`, `httpx` via Go;
`wappalyzer`, `retire` via npm; `semgrep` via pip), asking before each one. Nothing external gets
installed without you confirming it.

### Option 3 — Run without installing

```bash
git clone https://github.com/sobishirvanloo/jxray.git
cd jxray
pip install -r requirements.txt
python3 jxray/cli.py <url> [options]
```

### Editable / development install

```bash
pip install -e .
```

### Option 4 — Docker (no prerequisites but Docker itself)

Everything the core needs is baked into the image, so it runs the same on
Linux, macOS and Windows with nothing to install on the host but Docker.

```bash
docker build -t jxray .

# scan a URL; results land in ./out on the host (mounted at /work)
docker run --rm -v "$PWD/out:/work" jxray https://example.com \
    --all-analysis --report

# keep output files owned by you instead of root
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/work" \
    jxray https://example.com --endpoints --json

# analyze local files you drop into ./out  →  /work inside the container
docker run --rm -v "$PWD/out:/work" jxray --input-dir /work/js --all-analysis
```

Or with Compose:

```bash
docker compose run --rm jxray https://example.com --all-analysis --report
```

The default image includes **all static and network analysis** (endpoints,
params, secrets, DOM, CVE/OSV, GraphQL, config, replay, source-intel,
dependency-confusion, wayback). It does **not** include the headless browser
(`--dynamic`) or the external crawler binaries (katana/gau/httpx/retire/semgrep)
— for those, build the larger optional image:

```bash
docker build -f Dockerfile.full -t jxray:full .
docker run --rm -v "$PWD/out:/work" jxray:full https://example.com \
    --all-analysis --dynamic --katana --gau --httpx-probe --retire --semgrep --report
```

---

## Usage

Once installed, the `jxray` command is available globally:

```bash
jxray <url> [options]
```

Or, without installing:

```bash
python3 jxray/cli.py <url> [options]
```

### Targets: one URL, a list, or local files

Give exactly one of these:

```bash
jxray https://example.com [options]        # a single URL
jxray -l targets.txt [options]             # one URL per line ('#' comments ok; '-' = stdin)
jxray --input-dir ./some_js_dir [options]  # analyze .js already on disk, no network
```

- **`-l, --list FILE`** — batch mode. Every URL is scanned into its own sub-directory under
  `--output-dir` (`<output-dir>/<host>_<hash>/`). Invalid lines are skipped; the exit code is the
  worst seen across all targets. With `--json`, one results document is printed per target.
- **`--input-dir DIR`** — re-analyze JS you already have (a previous download, files pulled by hand,
  an unpacked bundle). It skips all network/discovery, beautifies each `.js`/`.mjs`/`.cjs` into
  `<output-dir>/local/`, and runs the same analyzers — so `file:line` in findings points at a real
  file. Network-only passes (`--dynamic`, `--katana`, `--gau`, `--wayback`, `--cve`, `--wappalyzer`)
  don't apply here.

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
--max-beautify-size MB       # fully beautify files up to this size; bigger ones get a fast
                             #   line-split instead, 0 = always beautify (default: 2)
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
--graphql                    # Extract GraphQL operations, fragments & client endpoints
--graphql-introspect         # Also send an introspection query to each endpoint found (active; live only)
--config                     # Extract config objects, feature flags, internal hosts, cloud resources, env-vars
--replay                     # Emit openapi.json + curl_commands.sh + ffuf_commands.sh from the endpoints
--source-intel               # Packages, project tree, dev emails & TODO/FIXME from recovered first-party code
--dep-confusion              # Flag imported packages unpublished on npm (claimable) — implies --source-intel (active)
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
--fail-on LIST               # Exit 3 if found: secrets,cves,hidden-endpoints,retire,semgrep,dom,dep-confusion
```

`results.json` is always written. It holds every finding (secrets unmasked), the file list, the
out-of-scope and skipped URLs, and run stats. Exit codes: `0` ok, `1` target unreachable,
`2` bad arguments, `3` a `--fail-on` category matched. `--fail-on X` turns on the analysis that
produces `X`.

```bash
# CI gate: fail the build if the deployed JS leaks a secret
jxray https://staging.example.com --fail-on secrets --json > js-results.json

# pipe endpoints into other tools
jxray https://example.com --endpoints --json | jq -r '.endpoints[]' | sort -u
```

### Examples

Through Burp, staying strictly on the target's domain:

```bash
jxray https://app.target.com \
  --proxy http://127.0.0.1:8080 --ca-cert burp.pem \
  --scope domain --exclude-host "*.google-analytics.com" \
  --cookie "session=abc123" --auth-scope domain \
  --endpoints --secrets --report
```

Basic static extraction:

```bash
jxray https://target.com
```

Full recon pass — dynamic extraction, deep crawl, historical URLs (alive-checked), all analysis, HTML report:

```bash
jxray https://target.com \
  --dynamic --katana --gau --httpx-probe --all-analysis --merge --report \
  --output-dir ./target_js
```

Historical JS only, without probing (faster, noisier):

```bash
jxray https://target.com --gau --gau-providers wayback,otx
```

Authenticated scan behind a login:

```bash
jxray https://target.com/dashboard \
  --cookie "session=abc123" \
  --header "X-Custom-Header: value" \
  --endpoints --secrets --cve
```

---

## Tutorial — your first scan, step by step

This walkthrough takes you from zero to a full recon pass and shows you how to read
every artefact. It assumes the Docker image is built (`docker build -t jxray .`);
if you installed with pip instead, just drop the `docker run ... jxray` prefix and
call `jxray` directly.

> Only scan targets you own or are explicitly authorized to test. Good practice targets:
> your own deployed app, a local lab (DVWA, Juice Shop, a Next.js/Vue app you built), or a
> bug-bounty program whose scope permits it.

### Step 1 — a first, quiet pass

Start with plain extraction: pull and beautify the JS, nothing active.

```bash
docker run --rm -v "$PWD/out:/work" jxray https://your-target.example
```

Look in `./out/`: `external/` holds each downloaded script beautified, `inline/` holds the
inline `<script>` blocks, and `results.json` summarizes the run. Open a file or two under
`external/` to confirm you're getting real application code.

### Step 2 — turn on the analysis

Now ask it to actually analyze what it pulled:

```bash
docker run --rm -v "$PWD/out:/work" jxray https://your-target.example \
    --endpoints --params --secrets --dom --report
```

Then read the results (all written under `./out/`):

| File | What to look for |
|------|------------------|
| `report.html` | Open in a browser — the human-friendly summary of everything below |
| `endpoints.txt` / `endpoints_hidden.txt` | API paths the front end calls; "hidden" = admin/internal/debug tokens |
| `params_wordlist.txt` | Parameter names that reach a request — feed these to a fuzzer |
| `secrets.json` | Leaked keys/tokens with severity and exact `file:line` (unmasked — handle with care) |
| `dom_sinks.json` | DOM-XSS sink/source flows to triage (then verify manually in a browser) |
| `results.json` | Everything, machine-readable, for piping into other tools |

### Step 3 — the full static pass

`--all-analysis` turns on every static analyzer (endpoints, params, secrets, DOM, CVE,
GraphQL, config, replay, source-intel) plus any external tools that are present:

```bash
docker run --rm -v "$PWD/out:/work" jxray https://your-target.example \
    --all-analysis --report
```

### Step 4 — make the findings actionable with `--replay`

`--replay` turns the endpoint list into things you can run:

```bash
docker run --rm -v "$PWD/out:/work" jxray https://your-target.example \
    --endpoints --params --replay \
    --cookie "session=YOUR_SESSION"        # if the app needs auth
```

- `out/openapi.json` — import into Postman/Insomnia or Swagger UI to browse the API.
- `out/curl_commands.sh` — one ready-to-run `curl` per endpoint, already carrying your auth.
- `out/ffuf_commands.sh` — parameter-fuzzing lines; run them with the `params_wordlist.txt`.

### Step 5 — GraphQL and dependency confusion

If the app speaks GraphQL, pull its operations and (with permission) probe the schema:

```bash
docker run --rm -v "$PWD/out:/work" jxray https://your-target.example \
    --graphql --graphql-introspect
# → out/graphql.json (operations, fragments, endpoints) and, if introspection is open,
#   out/graphql_schema.json
```

If source maps are available, mine the first-party code and check its packages against npm:

```bash
docker run --rm -v "$PWD/out:/work" jxray https://your-target.example \
    --source-intel --dep-confusion
# → out/source_intel.json (packages, project tree, emails, TODOs)
# → out/dep_confusion.json — any "claimable" package is a dependency-confusion candidate
```

### Step 6 — re-analyze files you already have (no network)

Already downloaded the JS, or pulled an app bundle apart? Analyze it offline:

```bash
# put the .js files under ./out/js  →  they appear at /work/js in the container
docker run --rm -v "$PWD/out:/work" jxray --input-dir /work/js --all-analysis --report
```

### Step 7 — scan many targets at once

```bash
# one URL per line in ./out/targets.txt  ('#' comments allowed)
docker run --rm -v "$PWD/out:/work" jxray -l /work/targets.txt --endpoints --secrets
# each target gets its own ./out/<host>_<hash>/ directory
```

### Step 8 — use it as a CI gate

`--fail-on` makes the process exit non-zero when something is found, so a pipeline can block on it:

```bash
jxray https://staging.example.com --fail-on secrets,cves --json > results.json
echo "exit code: $?"   # 0 = clean, 3 = a --fail-on category matched
```

**Exit codes:** `0` success · `1` target unreachable · `2` bad arguments · `3` a `--fail-on`
category matched · `130` interrupted (Ctrl+C).

### Need `--dynamic` or the crawler tools?

The default image is static-only. For the headless browser (`--dynamic`) and external crawlers
(`--katana`, `--gau`, `--httpx-probe`, `--retire`, `--semgrep`), build the full image once:

```bash
docker build -f Dockerfile.full -t jxray:full .
docker run --rm -v "$PWD/out:/work" jxray:full https://your-target.example \
    --all-analysis --dynamic --katana --gau --httpx-probe --retire --semgrep --report
```

---

## Output structure

```
js_output/
├── external/                # Downloaded + beautified external .js files
├── inline/                  # Beautified inline <script> blocks
├── local/                   # (with --input-dir) beautified copies of the local files analyzed
├── archived/                # (with --wayback) Wayback copies of scripts that are gone today
├── sourcemap_recovered/     # Original sources, one folder per bundle (+ _sources.txt index)
├── ALL_SCRIPTS_MERGED.js    # (with --merge)
├── endpoints.txt            # (with --endpoints)
├── endpoints_hidden.txt     # (with --endpoints)
├── gau_all.txt              # (with --gau, no probe)
├── gau_alive.txt            # (with --gau --httpx-probe) — "status_code  url" per line
├── params_wordlist.txt      # (with --params)
├── graphql.json             # (with --graphql) operations, fragments, client endpoints
├── graphql_schema.json      # (with --graphql-introspect) introspected schemas, if any were open
├── config.json              # (with --config) config objects, flags, internal hosts, cloud, env-vars
├── source_intel.json        # (with --source-intel) packages, tree, emails, TODO/FIXME
├── dep_confusion.json       # (with --dep-confusion) npm status per package (claimable = candidate)
├── openapi.json             # (with --replay) reconstructed OpenAPI 3.0 spec
├── curl_commands.sh         # (with --replay) one ready-to-run curl per endpoint (carries your auth)
├── ffuf_commands.sh         # (with --replay) parameter-fuzzing lines for ffuf
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
jxray/
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
