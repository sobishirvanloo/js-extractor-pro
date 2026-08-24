#!/usr/bin/env python3
"""
JS Extractor & Beautifier  (v2)
================================
Extracts, beautifies, and analyzes all JavaScript from a web page.

Features:
  - Static extraction (requests + BeautifulSoup)
  - Dynamic extraction via headless Chromium (Playwright)  [--dynamic]
  - Follows JS imports/chunks referenced inside script files
  - Parses source maps (.js.map) to recover original pre-bundle code
  - Extracts JS from Web Workers and Service Workers
  - Framework detection (React, Vue, Angular, Next.js, Nuxt, Svelte ...)
  - Deep crawl via katana to discover additional JS across the site [--katana]
  - API endpoint discovery                                 [--endpoints]
  - Hidden/internal endpoint highlighting
  - Parameter extraction for fuzzing                       [--params]
  - Secret/token/key pattern detection
  - Library version fingerprinting + CVE lookup (OSV.dev)  [--cve]
  - HTML report generation

Usage:
  python3 js_extractor.py <url> [options]

Auth:
  --cookie "name=value; name2=value2"
  --jwt    "eyJ..."
  --header "Key: Value"            (repeatable)

Extraction:
  --dynamic                        Use headless browser (captures lazy-loaded JS)
  --katana                         Deep-crawl the site with katana to find more JS files
  --katana-depth N                 Crawl depth for katana (default: 2)
  --no-inline                      Skip inline <script> blocks
  --no-external                    Skip external .js files
  --no-workers                     Skip Web Workers / Service Workers
  --no-sourcemaps                  Skip source map recovery
  --no-imports                     Skip following import/require chains

Analysis:
  --endpoints                      Extract API endpoints from all JS
  --params                         Extract parameters for fuzzing
  --secrets                        Scan for leaked keys/tokens/passwords
  --cve                            Fingerprint library versions & check OSV.dev for known CVEs
  --wappalyzer                     Run wappalyzer CLI for overall tech-stack fingerprinting
  --retire                         Run retire.js against downloaded JS (local CVE signatures)
  --semgrep                        Run semgrep static analysis (default: p/xss, p/javascript)
  --semgrep-config RULESET         Add/override semgrep ruleset (repeatable)
  --linkfinder                     Run LinkFinder against downloaded JS for endpoint extraction
  --linkfinder-path PATH           Path to linkfinder.py if not on PATH
  --all-analysis                   Enable all analysis flags above

Note on DOM Invader: live source→sink tracing in the browser (Burp Suite's
DOM Invader) isn't automatable from the CLI — it needs a human driving the
browser. This tool prepares everything DOM Invader needs (beautified JS,
endpoints, params) but the live-tracing step itself stays manual.

Output:
  --output-dir  ./js_output        Output directory (default: ./js_output)
  --merge                          Combine all scripts into one file
  --report                         Generate HTML analysis report
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import jsbeautifier

# Optional — only needed for --dynamic
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False

# Optional — only needed for source map parsing
try:
    import sourcemap as sourcemap_lib
    SOURCEMAP_OK = True
except ImportError:
    SOURCEMAP_OK = False


# ══════════════════════════════════════════════════════════════════════════════
# ANSI colours (disabled on Windows)
# ══════════════════════════════════════════════════════════════════════════════

import os
_USE_COLOR = sys.platform != "win32" and os.isatty(sys.stdout.fileno())

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP helpers
# ══════════════════════════════════════════════════════════════════════════════

def build_headers(args) -> dict:
    """Assemble request headers from CLI arguments."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if args.jwt:
        token = args.jwt.strip()
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def build_cookies(args) -> dict:
    """Parse --cookie string into a dict."""
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def fetch(url: str, session: requests.Session):
    """GET a URL. Returns Response or None on failure."""
    try:
        resp = session.get(url, timeout=20, allow_redirects=True)
        resp.raise_for_status()
        return resp
    except requests.exceptions.RequestException as e:
        print(f"  {yellow('[WARN]')} Could not fetch {url}: {e}", file=sys.stderr)
        return None


def resolve(src: str, base: str):
    """Resolve a relative URL against a base. Returns None for non-HTTP schemes."""
    src = src.strip()
    if not src or src.startswith("data:") or src.startswith("javascript:"):
        return None
    resolved = urljoin(base, src)
    return resolved if resolved.startswith("http") else None


def safe_filename(url: str, prefix: str = "script") -> str:
    """Generate a filesystem-safe unique filename from a URL."""
    parsed = urlparse(url)
    name = parsed.path.split("/")[-1] or "index"
    name = re.sub(r"[^\w\-.]", "_", name)
    if not name.endswith(".js"):
        name += ".js"
    short_hash = hashlib.md5(url.encode()).hexdigest()[:6]
    return f"{prefix}_{short_hash}_{name}"


# ══════════════════════════════════════════════════════════════════════════════
# Beautifier
# ══════════════════════════════════════════════════════════════════════════════

def beautify(js_code: str) -> str:
    """Prettify minified JavaScript with js-beautifier."""
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 2
    opts.wrap_line_length = 0
    opts.space_before_conditional = True
    opts.unescape_strings = True   # decode \\uXXXX and \\xXX sequences
    opts.jslint_happy = False
    opts.end_with_newline = True
    try:
        return jsbeautifier.beautify(js_code, opts)
    except Exception as e:
        return f"/* beautifier error: {e} */\n" + js_code


# ══════════════════════════════════════════════════════════════════════════════
# Static HTML extraction
# ══════════════════════════════════════════════════════════════════════════════

def extract_from_html(html: str, base_url: str):
    """
    Parse HTML for <script> tags.

    Returns:
      external_srcs : list[str]  -- absolute URLs from <script src="...">
      inline_blocks : list[str]  -- raw JS text from inline <script> tags
    """
    soup = BeautifulSoup(html, "html.parser")
    external_srcs, inline_blocks = [], []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            url = resolve(src, base_url)
            if url:
                external_srcs.append(url)
        else:
            code = tag.string or tag.get_text()
            if code and code.strip():
                inline_blocks.append(code.strip())

    return external_srcs, inline_blocks


# ══════════════════════════════════════════════════════════════════════════════
# Dynamic extraction with Playwright
# ══════════════════════════════════════════════════════════════════════════════

def extract_dynamic(url: str, args) -> tuple[list[str], list[str]]:
    """
    Launch a headless browser, wait for the page to fully load,
    and collect every script URL the browser actually requested.

    Returns (external_srcs, inline_blocks) same shape as extract_from_html.
    """
    if not PLAYWRIGHT_OK:
        print(red("[ERROR] Playwright not installed. Run: pip install playwright && playwright install chromium"))
        return [], []

    print(cyan("  [Browser] Launching headless Chromium..."))
    collected_urls = []
    inline_blocks = []

    # Build extra headers dict (without cookie — handled via context)
    extra_headers = {}
    if args.jwt:
        token = args.jwt.strip()
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        extra_headers["Authorization"] = token
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    # Parse cookies for Playwright
    pw_cookies = []
    parsed_base = urlparse(url)
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                pw_cookies.append({
                    "name": k.strip(),
                    "value": v.strip(),
                    "domain": parsed_base.hostname,
                    "path": "/",
                })

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            extra_http_headers=extra_headers,
            ignore_https_errors=True,
        )
        if pw_cookies:
            context.add_cookies(pw_cookies)

        page = context.new_page()

        # Intercept every network request
        def on_request(request):
            if request.resource_type == "script":
                collected_urls.append(request.url)

        page.on("request", on_request)
        page.goto(url, wait_until="networkidle", timeout=30000)

        # Also grab inline scripts from the live DOM
        scripts = page.evaluate("""
            () => Array.from(document.querySelectorAll('script:not([src])'))
                       .map(s => s.textContent)
                       .filter(t => t.trim().length > 0)
        """)
        inline_blocks.extend(scripts)

        # Wait a bit more for any late-loading chunks
        time.sleep(2)
        browser.close()

    print(cyan(f"  [Browser] Captured {len(collected_urls)} script request(s), {len(inline_blocks)} inline block(s)"))
    return collected_urls, inline_blocks


# ══════════════════════════════════════════════════════════════════════════════
# Import/require chain follower
# ══════════════════════════════════════════════════════════════════════════════

# Matches: import x from './chunk.js'  |  require('./util.js')  |  import('./lazy.js')
_IMPORT_RE = re.compile(
    r'''(?:import\s+.*?from\s+|require\s*\(\s*|import\s*\(\s*)['"`](\.{1,2}/[^'"`\s]+\.js(?:\?[^'"`\s]*)?)['"`]''',
    re.MULTILINE,
)

def find_js_imports(js_code: str, base_url: str) -> list[str]:
    """Extract relative JS import/require paths and resolve them against base_url."""
    found = []
    for m in _IMPORT_RE.finditer(js_code):
        resolved = resolve(m.group(1), base_url)
        if resolved:
            found.append(resolved)
    return found


# ══════════════════════════════════════════════════════════════════════════════
# Web Worker / Service Worker extraction
# ══════════════════════════════════════════════════════════════════════════════

_WORKER_RE = re.compile(
    r'''new\s+Worker\s*\(\s*['"`]([^'"`\s]+\.js[^'"`\s]*)['"`]'''
    r'''|navigator\.serviceWorker\.register\s*\(\s*['"`]([^'"`\s]+\.js[^'"`\s]*)['"`]''',
    re.MULTILINE,
)

def find_workers(js_code: str, base_url: str) -> list[str]:
    """Find Web Worker and Service Worker script URLs in JS source."""
    found = []
    for m in _WORKER_RE.finditer(js_code):
        src = m.group(1) or m.group(2)
        resolved = resolve(src, base_url)
        if resolved:
            found.append(resolved)
    return found


# ══════════════════════════════════════════════════════════════════════════════
# Source map recovery
# ══════════════════════════════════════════════════════════════════════════════

_SOURCEMAP_REF_RE = re.compile(
    r'//[#@]\s*sourceMappingURL=([^\s]+)', re.MULTILINE
)

def try_recover_sourcemap(js_code: str, js_url: str, session: requests.Session, out_dir: Path) -> int:
    """
    Look for a sourceMappingURL comment in the JS.
    If found, fetch the .map file and extract original source files.
    Returns the number of original files recovered.
    """
    if not SOURCEMAP_OK:
        return 0

    m = _SOURCEMAP_REF_RE.search(js_code)
    if not m:
        return 0

    map_ref = m.group(1).strip()

    # Inline base64 source map: sourceMappingURL=data:application/json;base64,<data>
    if map_ref.startswith("data:"):
        try:
            b64 = map_ref.split(",", 1)[1]
            map_json = base64.b64decode(b64).decode("utf-8")
        except Exception:
            return 0
    else:
        map_url = resolve(map_ref, js_url)
        if not map_url:
            return 0
        print(f"    {cyan('[SourceMap]')} Fetching: {map_url}")
        resp = fetch(map_url, session)
        if not resp:
            return 0
        map_json = resp.text

    try:
        sm = sourcemap_lib.loads(map_json)
    except Exception as e:
        print(f"    {yellow('[WARN]')} Could not parse source map: {e}")
        return 0

    recovered = 0
    sm_dir = out_dir / "sourcemap_recovered"
    sm_dir.mkdir(parents=True, exist_ok=True)

    for src_file in (sm.sources or []):
        try:
            content = sm.sources_content.get(src_file, "")
            if not content:
                continue
            # Keep relative path structure but make it safe
            safe_path = re.sub(r"[^\w/.\-]", "_", src_file).lstrip("/")
            dest = sm_dir / safe_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                f"/* Recovered from source map\n   Original: {src_file}\n   Map URL:  {js_url}\n*/\n\n"
                + beautify(content),
                encoding="utf-8",
            )
            recovered += 1
        except Exception:
            continue

    if recovered:
        print(f"    {green('[SourceMap]')} Recovered {recovered} original source file(s) → {sm_dir}")
    return recovered


# ══════════════════════════════════════════════════════════════════════════════
# Katana integration (optional deep crawl for additional JS files)
# ══════════════════════════════════════════════════════════════════════════════

def run_katana(url: str, depth: int = 2, headers: dict = None, cookies: dict = None,
                timeout: int = 180) -> list[str]:
    """
    Shell out to the katana crawler (ProjectDiscovery) to discover JS files
    across multiple pages of the site, beyond the single page fetched by
    requests/Playwright. Requires katana on PATH:
      go install github.com/projectdiscovery/katana/cmd/katana@latest

    Returns a deduplicated list of discovered .js URLs.
    """
    if shutil.which("katana") is None:
        print(f"  {yellow('[WARN]')} katana not found on PATH — skipping deep crawl.")
        print(f"  {yellow('[WARN]')} Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []

    cmd = ["katana", "-u", url, "-d", str(depth), "-silent", "-jc"]

    # katana accepts repeated -H "Key: Value" for custom headers (auth, cookie, etc.)
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]

    print(f"  {cyan('[Katana]')} Crawling {url} (depth={depth})... this can take a while")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} katana timed out after {timeout}s — using partial results")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} katana execution failed: {e}")
        return []

    if proc.returncode not in (0, None) and not proc.stdout.strip():
        print(f"  {yellow('[WARN]')} katana exited with code {proc.returncode}: {proc.stderr.strip()[:200]}")
        return []

    all_urls = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    # katana's plain output mixes all discovered URLs, so filter to .js ourselves
    js_urls = sorted(set(u for u in all_urls if u.split("?")[0].endswith(".js")))
    print(f"  {green('[Katana]')} Discovered {len(js_urls)} additional JS file(s) via crawl")
    return js_urls


# ══════════════════════════════════════════════════════════════════════════════
# gau integration (historical URL collection: Wayback / OTX / CommonCrawl / URLScan)
# ══════════════════════════════════════════════════════════════════════════════

def run_gau(domain: str, providers: list[str] = None, timeout: int = 180,
            blacklist: str = "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,css") -> list[str]:
    """
    Shell out to gau (getallurls, lc/gau) to pull every URL ever seen for a
    domain across the Wayback Machine, AlienVault OTX, CommonCrawl and
    URLScan. This surfaces old/forgotten JS bundles, endpoints, and params
    that a live crawl (katana) would never find because the page no longer
    links to them. Requires gau on PATH:
      go install github.com/lc/gau/v2/cmd/gau@latest

    Returns a deduplicated list of URLs (all types — filter to .js yourself
    if you only want scripts).
    """
    if shutil.which("gau") is None:
        print(f"  {yellow('[WARN]')} gau not found on PATH — skipping historical URL collection.")
        print(f"  {yellow('[WARN]')} Install with: go install github.com/lc/gau/v2/cmd/gau@latest")
        return []

    cmd = ["gau", "--subs"]
    if blacklist:
        cmd += ["--blacklist", blacklist]
    if providers:
        cmd += ["--providers", ",".join(providers)]
    cmd += [domain]

    print(f"  {cyan('[gau]')} Pulling historical URLs for {domain} (Wayback/OTX/CommonCrawl/URLScan)...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} gau timed out after {timeout}s — using partial results")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} gau execution failed: {e}")
        return []

    if proc.returncode not in (0, None) and not proc.stdout.strip():
        print(f"  {yellow('[WARN]')} gau exited with code {proc.returncode}: {proc.stderr.strip()[:200]}")
        return []

    urls = sorted(set(line.strip() for line in proc.stdout.splitlines() if line.strip()))
    print(f"  {green('[gau]')} Collected {len(urls)} historical URL(s)")
    return urls


def run_httpx_probe(urls: list[str], headers: dict = None, cookies: dict = None,
                     threads: int = 50, timeout: int = 300) -> list[dict]:
    """
    Shell out to httpx (ProjectDiscovery's HTTP toolkit — NOT the Python
    `httpx` library) to probe a list of URLs and report which are alive,
    with status code, title, content-length and tech detection. Used to
    filter noisy gau output down to URLs that actually resolve today.
    Requires the httpx CLI on PATH:
      go install github.com/projectdiscovery/httpx/cmd/httpx@latest

    Returns a list of dicts (parsed from httpx's -json output), one per
    live URL.
    """
    if not urls:
        return []
    if shutil.which("httpx") is None:
        print(f"  {yellow('[WARN]')} httpx not found on PATH — skipping alive-check.")
        print(f"  {yellow('[WARN]')} Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return []

    cmd = ["httpx", "-silent", "-json", "-follow-redirects",
           "-status-code", "-title", "-content-length", "-tech-detect",
           "-threads", str(threads)]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]

    print(f"  {cyan('[httpx]')} Probing {len(urls)} URL(s) for liveness...")
    try:
        proc = subprocess.run(
            cmd, input="\n".join(urls), capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} httpx timed out after {timeout}s — using partial results")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} httpx execution failed: {e}")
        return []

    results = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    print(f"  {green('[httpx]')} {len(results)}/{len(urls)} URL(s) alive")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: framework detection
# ══════════════════════════════════════════════════════════════════════════════

_FRAMEWORK_SIGS = [
    ("React",       [r'React\.createElement', r'__SECRET_INTERNALS_DO_NOT_USE', r'react-dom']),
    ("Next.js",     [r'__NEXT_DATA__', r'next/router', r'_next/static']),
    ("Vue",         [r'Vue\.component', r'__vue_component__', r'createApp\s*\(']),
    ("Nuxt",        [r'__nuxt', r'nuxtApp', r'\$nuxt']),
    ("Angular",     [r'angular\.module', r'ng-version', r'@angular/core']),
    ("Svelte",      [r'SvelteComponent', r'__svelte', r'svelte/internal']),
    ("Ember",       [r'Ember\.Application', r'ember-source']),
    ("Backbone",    [r'Backbone\.Model', r'Backbone\.View']),
    ("jQuery",      [r'jQuery\.fn', r'\$\.ajax\s*\(']),
    ("Webpack",     [r'__webpack_require__', r'webpackChunk']),
    ("Vite",        [r'import\.meta\.hot', r'/@vite/client']),
    ("GraphQL",     [r'gql`', r'ApolloClient', r'graphql-ws']),
]

def detect_frameworks(all_js: str) -> list[str]:
    """Scan combined JS text for framework fingerprints."""
    detected = []
    for name, patterns in _FRAMEWORK_SIGS:
        if any(re.search(p, all_js) for p in patterns):
            detected.append(name)
    return detected


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: endpoint extraction
# ══════════════════════════════════════════════════════════════════════════════

# Patterns ordered from most specific to most general
_ENDPOINT_PATTERNS = [
    # fetch/axios/http explicit calls
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*[`'"]((?:https?://[^`'"]{3,}|/[^`'"]{2,}))[`'"]''',
    # url/path/endpoint/href assignments
    r'''(?:url|path|endpoint|baseURL|baseUrl|apiUrl|href)\s*[:=]\s*[`'"]((?:https?://[^`'"]{4,}|/[^`'"]{2,}))[`'"]''',
    # string literals that look like API paths
    r'''[`'"]((?:/api|/v\d+|/graphql|/rest|/rpc|/internal|/admin|/auth|/oauth|/ws)[^`'"\s<>{}]{1,120})[`'"]''',
    # template literals with path prefix
    r'''`((?:/api|/v\d+|/internal|/admin)[^`]{1,120})`''',
]

# Paths that look like sensitive/hidden endpoints
_HIDDEN_MARKERS = re.compile(
    r'(?:internal|debug|admin|secret|hidden|private|test|dev|staging|backdoor|console|panel)',
    re.IGNORECASE,
)

_SKIP_EXTENSIONS = re.compile(r'\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|ico|map)(\?.*)?$', re.IGNORECASE)


def extract_endpoints(js_code: str) -> tuple[list[str], list[str]]:
    """
    Extract API endpoint strings from JavaScript source.

    Returns:
      endpoints : list[str]  -- all found endpoints
      hidden    : list[str]  -- subset that look sensitive/internal
    """
    found = set()
    for pat in _ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js_code, re.MULTILINE | re.IGNORECASE):
            ep = m.group(1).strip()
            # Filter noise
            if len(ep) < 2:
                continue
            if _SKIP_EXTENSIONS.search(ep):
                continue
            # Remove template-literal expressions like ${id}
            ep_clean = re.sub(r'\$\{[^}]+\}', '{param}', ep)
            found.add(ep_clean)

    endpoints = sorted(found)
    hidden = [e for e in endpoints if _HIDDEN_MARKERS.search(e)]
    return endpoints, hidden


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: parameter extraction
# ══════════════════════════════════════════════════════════════════════════════

_PARAM_PATTERNS = [
    # Query string params: ?foo=  &bar=
    r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=',
    # Object key patterns in request bodies: { userId: ..., limit: ... }
    r'''[{,]\s*['"]?([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]?\s*:''',
    # URLSearchParams / FormData .append / .set / .get calls
    r'''(?:\.append|\.set|\.get|\.has)\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]''',
    # express-style route params: /users/:id, /orders/:orderId
    r'''['"`]/[^'"`\s]*/:([a-zA-Z_][a-zA-Z0-9_\-]{1,40})''',
    # input name= attributes inside template strings / HTML in JS
    r'''name\s*=\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]''',
    # HTML form fields in string literals
    r'''<input[^>]+name\s*=\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]''',
]

# Noise words to exclude from param results
_PARAM_NOISE = {
    "function", "return", "const", "let", "var", "class", "import", "export",
    "default", "true", "false", "null", "undefined", "this", "new", "typeof",
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "try", "catch", "throw", "async", "await", "yield", "of", "in",
    "prototype", "constructor", "toString", "length", "push", "pop", "map",
    "filter", "reduce", "forEach", "find", "some", "every", "then", "catch",
    "resolve", "reject", "data", "error", "event", "result", "response",
    "request", "options", "config", "params", "props", "state", "value",
    "type", "name", "text", "html", "body", "head", "style", "src", "href",
}

def extract_params(js_code: str, html_code: str = "") -> list[str]:
    """
    Extract parameter names from JS (and optionally HTML) for use in fuzzing.
    Returns a deduplicated, sorted list.
    """
    combined = js_code + "\n" + html_code
    found = set()

    for pat in _PARAM_PATTERNS:
        for m in re.finditer(pat, combined, re.MULTILINE | re.IGNORECASE):
            p = m.group(1).strip()
            if p.lower() not in _PARAM_NOISE and 2 <= len(p) <= 40:
                found.add(p)

    return sorted(found, key=str.lower)


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: secret / credential detection
# ══════════════════════════════════════════════════════════════════════════════

_SECRET_PATTERNS = [
    # Generic key/secret assignments
    (r'''(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,})['"`]''', "API Key"),
    (r'''(?:secret|client_secret|app_secret)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]''', "Secret"),
    (r'''(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]''', "Password"),
    # Specific service formats
    (r'(sk-[a-zA-Z0-9]{20,})', "OpenAI SK Key"),
    (r'(sk-proj-[a-zA-Z0-9_\-]{20,})', "OpenAI Project Key"),
    (r'(AIza[A-Za-z0-9_\-]{35})', "Google API Key"),
    (r'(AKIA[A-Z0-9]{16})', "AWS Access Key"),
    (r'(gh[pousr]_[A-Za-z0-9_]{36,})', "GitHub Token"),
    (r'(glpat-[A-Za-z0-9\-_]{20,})', "GitLab Token"),
    (r'(xox[baprs]-[A-Za-z0-9\-]+)', "Slack Token"),
    (r'(EAA[A-Za-z0-9]{50,})', "Facebook Token"),
    # JWT
    (r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})', "JWT Token"),
    # Private keys
    (r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)', "Private Key Block"),
    # Hex secrets (32+ hex chars after key indicator)
    (r'''(?:secret|token|key)\s*[:=]\s*['"`]([0-9a-fA-F]{32,})['"`]''', "Hex Secret"),
]

def find_secrets(js_code: str) -> list[dict]:
    """
    Scan JS source for leaked credentials/tokens.

    Returns list of { type, value, line } dicts.
    """
    lines = js_code.split("\n")
    results = []
    seen = set()

    for pat, label in _SECRET_PATTERNS:
        for m in re.finditer(pat, js_code, re.IGNORECASE | re.MULTILINE):
            val = m.group(1)
            key = (label, val[:30])
            if key in seen:
                continue
            seen.add(key)
            # Find line number
            line_no = js_code[:m.start()].count("\n") + 1
            results.append({"type": label, "value": val, "line": line_no})

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: library version fingerprinting
# ══════════════════════════════════════════════════════════════════════════════

# (regex, npm_package_name) — matched against banner comments and filenames
# that ship inside the unminified/beautified JS. Ordered roughly by how
# commonly each library appears in the wild.
_LIB_VERSION_PATTERNS = [
    (r'jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)', "jquery"),
    (r'jquery[.\-]?(\d+\.\d+\.\d+)(?:\.min)?\.js', "jquery"),
    (r'jquery-ui[.\-]?(\d+\.\d+\.\d+)', "jquery-ui"),
    (r'AngularJS\s+v?(\d+\.\d+\.\d+)', "angular"),
    (r'angular[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "angular"),
    (r'@angular/core["\']?\s*[:=]\s*["\']?\^?(\d+\.\d+\.\d+)', "@angular/core"),
    (r'React\s+v?(\d+\.\d+\.\d+)', "react"),
    (r'react[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "react"),
    (r'Vue\.js\s+v(\d+\.\d+\.\d+)', "vue"),
    (r'vue@(\d+\.\d+\.\d+)', "vue"),
    (r'Lodash\s+v?(\d+\.\d+\.\d+)', "lodash"),
    (r'lodash[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "lodash"),
    (r'moment\.js\s+v?(\d+\.\d+\.\d+)', "moment"),
    (r'moment[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "moment"),
    (r'Bootstrap\s+v(\d+\.\d+\.\d+)', "bootstrap"),
    (r'bootstrap[.\-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)', "bootstrap"),
    (r'[Hh]andlebars\.js\s+v(\d+\.\d+\.\d+)', "handlebars"),
    (r'Underscore\.js\s+(\d+\.\d+\.\d+)', "underscore"),
    (r'Backbone\.js\s+(\d+\.\d+\.\d+)', "backbone"),
    (r'[Dd]3\.js\s+v?(\d+\.\d+\.\d+)', "d3"),
    (r'd3[.\-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js', "d3"),
    (r'axios\s+v(\d+\.\d+\.\d+)', "axios"),
    (r'[Ss]ocket\.IO\s+v?(\d+\.\d+\.\d+)', "socket.io"),
    (r'ag-[Gg]rid[^\d\n]{0,20}(\d+\.\d+\.\d+)', "ag-grid-community"),
    (r'ckeditor[.\-]?(\d+\.\d+\.\d+)', "ckeditor4"),
    (r'tinymce[.\-]?(\d+\.\d+\.\d+)', "tinymce"),
    (r'swagger-ui[.\-]?(\d+\.\d+\.\d+)', "swagger-ui"),
]

def detect_library_versions(all_js: str) -> list[dict]:
    """
    Scan combined JS text for embedded library name/version banners
    (common in unminified or lightly-minified bundles — beautify() run
    earlier in the pipeline makes these much easier to spot).

    Returns a deduplicated list of {"name": npm_package_name, "version": x.y.z}.
    Only as good as what's actually visible in the shipped JS: minified
    bundles that strip comments and rename everything will yield fewer hits.
    """
    found = {}
    for pattern, name in _LIB_VERSION_PATTERNS:
        for m in re.finditer(pattern, all_js, re.IGNORECASE):
            version = m.group(1)
            key = (name, version)
            if key not in found:
                found[key] = {"name": name, "version": version}
    return sorted(found.values(), key=lambda l: (l["name"], l["version"]))


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: CVE lookup via OSV.dev (public vulnerability database)
# ══════════════════════════════════════════════════════════════════════════════

_OSV_API_URL = "https://api.osv.dev/v1/query"

def lookup_cves(libraries: list[dict], timeout: int = 10) -> list[dict]:
    """
    For each detected {name, version}, query OSV.dev — a free, public
    vulnerability database that aggregates GitHub Security Advisories,
    npm advisories, and NVD-derived records. This mirrors what retire.js
    does locally, but stays current without needing a bundled/offline DB.

    Returns a list of:
      { library, version, id, cve, summary, severity, url }
    """
    results = []
    for lib in libraries:
        payload = {
            "version": lib["version"],
            "package": {"name": lib["name"], "ecosystem": "npm"},
        }
        try:
            resp = requests.post(_OSV_API_URL, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"  {yellow('[WARN]')} OSV lookup failed for {lib['name']}@{lib['version']}: {e}",
                  file=sys.stderr)
            continue

        for vuln in data.get("vulns", []):
            severity = ""
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    severity = sev.get("score", "")
                    break
            aliases = vuln.get("aliases", []) or []
            cve_id = next((a for a in aliases if a.startswith("CVE-")), "")
            summary = (vuln.get("summary") or vuln.get("details") or "").strip()
            results.append({
                "library": lib["name"],
                "version": lib["version"],
                "id": vuln.get("id", ""),
                "cve": cve_id,
                "summary": summary[:300],
                "severity": severity,
                "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
            })
        time.sleep(0.2)  # polite pacing against the public API

    return results


# ══════════════════════════════════════════════════════════════════════════════
# External tool integrations (wappalyzer, retire.js, semgrep, linkfinder)
# ══════════════════════════════════════════════════════════════════════════════
#
# These wrap the same command-line tools used in the manual workflow:
#   wappalyzer https://target.com
#   retire --path ./downloaded_js --outputformat json
#   semgrep --config "p/xss" ./downloaded_js
#   python3 linkfinder.py -i './downloaded_js/*.js' -o cli
#
# Each function checks the binary is on PATH first and degrades gracefully
# (prints a warning + install hint, returns an empty result) if it isn't —
# same pattern as run_katana() above.

def run_wappalyzer(url: str, timeout: int = 60) -> list[dict]:
    """
    Run the wappalyzer CLI (npm install -g wappalyzer) against the target
    URL for overall tech-stack fingerprinting (frameworks, servers, CMS,
    analytics, etc.) — broader than the in-JS signature matching we do
    ourselves in detect_frameworks()/detect_library_versions().

    Returns a list of {"name": str, "version": str, "categories": [str]}.
    """
    if shutil.which("wappalyzer") is None:
        print(f"  {yellow('[WARN]')} wappalyzer not found on PATH — skipping tech detection.")
        print(f"  {yellow('[WARN]')} Install: npm install -g wappalyzer")
        return []

    print(f"  {cyan('[Wappalyzer]')} Fingerprinting tech stack for {url}...")
    try:
        proc = subprocess.run(
            ["wappalyzer", url],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} wappalyzer timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} wappalyzer execution failed: {e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  {yellow('[WARN]')} Could not parse wappalyzer output as JSON")
        return []

    # wappalyzer CLI output shape: {"urls": {...}, "technologies": [...]}
    techs = data.get("technologies", data if isinstance(data, list) else [])
    results = []
    for t in techs:
        results.append({
            "name": t.get("name", "unknown"),
            "version": t.get("version") or "",
            "categories": [c.get("name", "") for c in t.get("categories", [])],
        })

    print(f"  {green('[Wappalyzer]')} Identified {len(results)} technolog{'y' if len(results) == 1 else 'ies'}")
    return results


def run_retire(js_dir: Path, timeout: int = 120) -> list[dict]:
    """
    Run retire.js (npm install -g retire) against a directory of downloaded
    JS files. This is a local, signature-based CVE scanner — a useful
    complement to the live OSV.dev lookup in lookup_cves(), since it also
    catches hash-fingerprinted minified files that carry no version banner.

    Returns a list of {"file", "component", "version", "vulnerabilities": [...]}.
    """
    if shutil.which("retire") is None:
        print(f"  {yellow('[WARN]')} retire.js not found on PATH — skipping local CVE scan.")
        print(f"  {yellow('[WARN]')} Install: npm install -g retire")
        return []
    if not js_dir.exists() or not any(js_dir.iterdir()):
        print(f"  {yellow('[WARN]')} No downloaded JS directory to scan with retire.js")
        return []

    print(f"  {cyan('[retire.js]')} Scanning {js_dir} for known-vulnerable components...")
    try:
        proc = subprocess.run(
            ["retire", "--path", str(js_dir), "--outputformat", "json", "--severity", "low"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} retire.js timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} retire.js execution failed: {e}")
        return []

    # retire exits non-zero when it finds vulnerabilities — that's expected,
    # so don't treat returncode != 0 as failure; only missing JSON is fatal.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  {yellow('[WARN]')} Could not parse retire.js output as JSON")
        return []

    results = []
    for entry in data.get("data", []):
        fname = entry.get("file", "")
        for result in entry.get("results", []):
            component = result.get("component", "unknown")
            version = result.get("version", "")
            vulns = result.get("vulnerabilities", [])
            if vulns:
                results.append({
                    "file": fname,
                    "component": component,
                    "version": version,
                    "vulnerabilities": [
                        {
                            "info": v.get("info", []),
                            "identifiers": v.get("identifiers", {}),
                            "severity": v.get("severity", ""),
                        }
                        for v in vulns
                    ],
                })

    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    print(f"  {green('[retire.js]')} {len(results)} vulnerable component instance(s), "
          f"{total_vulns} finding(s) total")
    return results


def run_semgrep(target_dir: Path, configs: list[str] = None, timeout: int = 300) -> list[dict]:
    """
    Run semgrep static analysis against downloaded/extracted JS for
    dangerous client-side patterns (matches the manual step:
    `semgrep --config "p/xss" ./`).

    Returns a list of {"rule_id", "file", "line", "message", "severity"}.
    """
    if shutil.which("semgrep") is None:
        print(f"  {yellow('[WARN]')} semgrep not found on PATH — skipping static analysis.")
        print(f"  {yellow('[WARN]')} Install: pip install semgrep  (or: pip install --break-system-packages semgrep)")
        return []
    if not target_dir.exists() or not any(target_dir.iterdir()):
        print(f"  {yellow('[WARN]')} No JS directory to scan with semgrep")
        return []

    configs = configs or ["p/xss", "p/javascript"]
    cmd = ["semgrep", "--json", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(str(target_dir))

    print(f"  {cyan('[semgrep]')} Running static analysis ({', '.join(configs)}) on {target_dir}...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} semgrep timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} semgrep execution failed: {e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  {yellow('[WARN]')} Could not parse semgrep output as JSON: {proc.stderr[:200]}")
        return []

    results = []
    for r in data.get("results", []):
        results.append({
            "rule_id": r.get("check_id", ""),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "message": (r.get("extra", {}).get("message", "") or "").strip()[:300],
            "severity": r.get("extra", {}).get("severity", ""),
        })

    print(f"  {green('[semgrep]')} {len(results)} finding(s)")
    return results


def run_linkfinder(target_dir: Path, linkfinder_path: str = "", timeout: int = 120) -> list[str]:
    """
    Run LinkFinder (https://github.com/GerbenJavado/LinkFinder) against every
    .js file in target_dir to extract endpoint-like strings — a complement to
    our own extract_endpoints() regex pass, using LinkFinder's own patterns.

    LinkFinder isn't a pip package with a stable console-script name, so this
    looks for (in order): an explicit --linkfinder-path, a `linkfinder`
    binary on PATH, or a `linkfinder.py` on PATH.

    Returns a deduplicated, sorted list of endpoint strings.
    """
    lf_cmd = None
    if linkfinder_path:
        lf_cmd = [sys.executable, linkfinder_path]
    elif shutil.which("linkfinder"):
        lf_cmd = ["linkfinder"]
    elif shutil.which("linkfinder.py"):
        lf_cmd = [sys.executable, shutil.which("linkfinder.py")]

    if lf_cmd is None:
        print(f"  {yellow('[WARN]')} LinkFinder not found — skipping.")
        print(f"  {yellow('[WARN]')} Install: git clone https://github.com/GerbenJavado/LinkFinder && "
              f"pip install -r LinkFinder/requirements.txt, then pass --linkfinder-path /path/to/linkfinder.py")
        return []
    if not target_dir.exists():
        return []

    js_files = list(target_dir.rglob("*.js"))
    if not js_files:
        print(f"  {yellow('[WARN]')} No .js files under {target_dir} for LinkFinder to scan")
        return []

    print(f"  {cyan('[LinkFinder]')} Scanning {len(js_files)} file(s)...")
    found = set()
    for jf in js_files:
        try:
            proc = subprocess.run(
                lf_cmd + ["-i", str(jf), "-o", "cli"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"  {yellow('[WARN]')} LinkFinder timed out on {jf.name}")
            continue
        except Exception as e:
            print(f"  {yellow('[WARN]')} LinkFinder failed on {jf.name}: {e}")
            continue
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                found.add(line)

    results = sorted(found)
    print(f"  {green('[LinkFinder]')} {len(results)} unique endpoint(s) found")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# File I/O
# ══════════════════════════════════════════════════════════════════════════════

def save_js(content: str, path: Path, url: str = "") -> None:
    """Write beautified JS to disk with an optional source comment header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    header = f"/* Source: {url} */\n\n" if url else ""
    path.write_text(header + content, encoding="utf-8")
    print(f"  {green('[OK]')} Saved -> {path.name}")


# ══════════════════════════════════════════════════════════════════════════════
# HTML Report generator
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(data: dict, out_dir: Path) -> Path:
    """Build a self-contained HTML analysis report."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def badge(text, color):
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{text}</span>'

    def section(title, content_html, color="#2563eb"):
        return f"""
        <details open>
          <summary style="cursor:pointer;padding:10px;background:{color}15;border-left:4px solid {color};
                          font-weight:bold;font-size:15px;list-style:none">{title}</summary>
          <div style="padding:12px 16px">{content_html}</div>
        </details>"""

    # ── Files table ──────────────────────────────────────────────────────────
    file_rows = ""
    for f in data.get("files", []):
        kind_badge = badge(f["kind"], "#6366f1" if f["kind"] == "external" else "#0891b2")
        file_rows += f"""<tr>
          <td>{kind_badge}</td>
          <td style="word-break:break-all"><a href="{f['saved_path']}" target="_blank">{f['filename']}</a></td>
          <td><a href="{f['url']}" target="_blank" style="font-size:11px">{f['url'][:80]}{'...' if len(f['url'])>80 else ''}</a></td>
          <td>{f['size_kb']:.1f} KB</td>
        </tr>"""
    files_html = f"""
    <table style="width:100%;border-collapse:collapse">
      <tr style="background:#f1f5f9;font-weight:bold">
        <th style="padding:8px;text-align:left">Type</th>
        <th style="padding:8px;text-align:left">File</th>
        <th style="padding:8px;text-align:left">Source URL</th>
        <th style="padding:8px;text-align:left">Size</th>
      </tr>
      {file_rows}
    </table>"""

    # ── Frameworks ───────────────────────────────────────────────────────────
    fw_html = " ".join(badge(f, "#7c3aed") for f in data.get("frameworks", [])) or "<i>None detected</i>"

    # ── Endpoints ────────────────────────────────────────────────────────────
    ep_rows = ""
    for ep in data.get("endpoints", []):
        is_hidden = ep in data.get("hidden_endpoints", [])
        flag = f' {badge("HIDDEN", "#dc2626")}' if is_hidden else ""
        ep_rows += f"<tr><td style='padding:5px;font-family:monospace;word-break:break-all'>{ep}{flag}</td></tr>\n"
    ep_html = f"<table style='width:100%;border-collapse:collapse'>{ep_rows}</table>" if ep_rows else "<i>No endpoints extracted (use --endpoints)</i>"

    # ── Params ───────────────────────────────────────────────────────────────
    param_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;display:inline-block">{p}</code>'
        for p in data.get("params", [])
    ) or "<i>No params extracted (use --params)</i>"

    # Wordlist file path
    wordlist_note = ""
    if data.get("params"):
        wordlist_note = f'<p style="margin-top:8px">📄 Wordlist saved to: <code>{data.get("wordlist_path","")}</code></p>'

    # ── Secrets ──────────────────────────────────────────────────────────────
    sec_rows = ""
    for s in data.get("secrets", []):
        # Mask the middle of the secret value
        val = s["value"]
        masked = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "..."
        sec_rows += (
            f"<tr>"
            f"<td style='padding:5px'>{badge(s['type'], '#dc2626')}</td>"
            f"<td style='padding:5px;font-family:monospace'>{masked}</td>"
            f"<td style='padding:5px'>Line {s['line']}</td>"
            f"</tr>\n"
        )
    sec_html = (
        f"<table style='width:100%;border-collapse:collapse'>{sec_rows}</table>"
        if sec_rows else "<i>No secrets found (use --secrets)</i>"
    )

    # ── Libraries & CVEs ─────────────────────────────────────────────────────
    cves_by_lib = defaultdict(list)
    for c in data.get("cves", []):
        cves_by_lib[(c["library"], c["version"])].append(c)

    lib_rows = ""
    for l in data.get("libraries", []):
        key = (l["name"], l["version"])
        hits = cves_by_lib.get(key, [])
        if hits:
            cve_badges = " ".join(
                f'<a href="{c["url"]}" target="_blank">{badge(c["cve"] or c["id"], "#dc2626")}</a>'
                for c in hits
            )
            status = cve_badges
        else:
            status = badge("no known CVEs", "#16a34a")
        lib_rows += f"""<tr>
          <td style="padding:5px;font-family:monospace">{l['name']}</td>
          <td style="padding:5px;font-family:monospace">{l['version']}</td>
          <td style="padding:5px">{status}</td>
        </tr>"""
    lib_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">Library</th>
                <th style="padding:8px;text-align:left">Version</th>
                <th style="padding:8px;text-align:left">Known CVEs (via OSV.dev)</th>
              </tr>{lib_rows}
            </table>"""
        if lib_rows else "<i>No version-fingerprinted libraries detected (use --cve)</i>"
    )

    cve_detail_rows = ""
    for c in data.get("cves", []):
        cve_detail_rows += f"""<tr>
          <td style="padding:5px">{badge(c['cve'] or c['id'], '#dc2626')}</td>
          <td style="padding:5px;font-family:monospace">{c['library']}@{c['version']}</td>
          <td style="padding:5px">{c['severity'] or '<i>n/a</i>'}</td>
          <td style="padding:5px;font-size:12px">{c['summary']}</td>
          <td style="padding:5px"><a href="{c['url']}" target="_blank">osv.dev</a></td>
        </tr>"""
    cve_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">ID</th>
                <th style="padding:8px;text-align:left">Library</th>
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">Summary</th>
                <th style="padding:8px;text-align:left">Link</th>
              </tr>{cve_detail_rows}
            </table>"""
        if cve_detail_rows else "<i>No known CVEs matched (or --cve was not used)</i>"
    )

    # ── Technologies (wappalyzer) ────────────────────────────────────────────
    tech_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;display:inline-block">'
        f'{t["name"]}{" v" + t["version"] if t["version"] else ""}</code>'
        for t in data.get("technologies", [])
    ) or "<i>No tech-stack data (use --wappalyzer)</i>"

    # ── retire.js findings ───────────────────────────────────────────────────
    retire_rows = ""
    for r in data.get("retire_findings", []):
        for v in r["vulnerabilities"]:
            ids = v.get("identifiers", {})
            cve_list = ids.get("CVE", [])
            label = ", ".join(cve_list) if cve_list else (ids.get("summary", "") or "unlabeled")
            retire_rows += f"""<tr>
              <td style="padding:5px">{badge(label, '#dc2626')}</td>
              <td style="padding:5px;font-family:monospace">{r['component']}@{r['version']}</td>
              <td style="padding:5px">{v.get('severity', '') or '<i>n/a</i>'}</td>
              <td style="padding:5px;font-size:12px;word-break:break-all">{r['file']}</td>
            </tr>"""
    retire_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">ID</th>
                <th style="padding:8px;text-align:left">Component</th>
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">File</th>
              </tr>{retire_rows}
            </table>"""
        if retire_rows else "<i>No retire.js findings (or --retire was not used)</i>"
    )

    # ── semgrep findings ──────────────────────────────────────────────────────
    semgrep_rows = ""
    for s in data.get("semgrep_findings", []):
        semgrep_rows += f"""<tr>
          <td style="padding:5px">{badge(s['severity'] or 'INFO', '#b45309')}</td>
          <td style="padding:5px;font-family:monospace;font-size:12px">{s['rule_id']}</td>
          <td style="padding:5px;font-size:12px">{s['file']}:{s['line']}</td>
          <td style="padding:5px;font-size:12px">{s['message']}</td>
        </tr>"""
    semgrep_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">Rule</th>
                <th style="padding:8px;text-align:left">Location</th>
                <th style="padding:8px;text-align:left">Message</th>
              </tr>{semgrep_rows}
            </table>"""
        if semgrep_rows else "<i>No semgrep findings (or --semgrep was not used)</i>"
    )

    # ── LinkFinder endpoints ──────────────────────────────────────────────────
    lf_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;'
        f'display:inline-block;word-break:break-all">{e}</code>'
        for e in data.get("linkfinder_endpoints", [])
    ) or "<i>No LinkFinder results (or --linkfinder was not used)</i>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>JS Extractor Report — {data['target_url']}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 0; background: #f8fafc; color: #1e293b; }}
  .wrap {{ max-width: 1100px; margin: auto; padding: 24px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 20px; min-width: 120px; }}
  .stat-num {{ font-size: 28px; font-weight: bold; color: #2563eb; }}
  .stat-lbl {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
  details {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  table tr:nth-child(even) {{ background: #f8fafc; }}
  a {{ color: #2563eb; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔍 JS Extractor Report</h1>
  <div class="meta">
    Target: <a href="{data['target_url']}" target="_blank">{data['target_url']}</a>
    &nbsp;|&nbsp; Generated: {ts}
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-num">{data['total_files']}</div><div class="stat-lbl">JS Files</div></div>
    <div class="stat"><div class="stat-num">{data['total_size_kb']:.0f} KB</div><div class="stat-lbl">Total Size</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('endpoints', []))}</div><div class="stat-lbl">Endpoints</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('hidden_endpoints', []))}</div><div class="stat-lbl">Hidden Endpoints</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('params', []))}</div><div class="stat-lbl">Parameters</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('secrets', []))}</div><div class="stat-lbl">Secrets Found</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('libraries', []))}</div><div class="stat-lbl">Libraries Fingerprinted</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('cves', []))}</div><div class="stat-lbl">Known CVEs</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('technologies', []))}</div><div class="stat-lbl">Technologies</div></div>
    <div class="stat"><div class="stat-num">{sum(len(r['vulnerabilities']) for r in data.get('retire_findings', []))}</div><div class="stat-lbl">retire.js Findings</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('semgrep_findings', []))}</div><div class="stat-lbl">semgrep Findings</div></div>
  </div>

  {section("🔧 Detected Frameworks", fw_html, "#7c3aed")}
  {section("🧩 Technologies (Wappalyzer)", tech_chips, "#7c3aed")}
  {section("📁 Extracted Files", files_html, "#2563eb")}
  {section("🔗 API Endpoints", ep_html, "#0891b2")}
  {section("🔗 LinkFinder Endpoints", lf_chips, "#0891b2")}
  {section("🔑 Parameters (Fuzzing Wordlist)", param_chips + wordlist_note, "#059669")}
  {section("⚠️ Potential Secrets / Credentials", sec_html, "#dc2626")}
  {section("📦 Library Versions", lib_html, "#0f766e")}
  {section("🛡️ Known CVEs (OSV.dev)", cve_html, "#b91c1c")}
  {section("🛡️ retire.js Findings (local signature scan)", retire_html, "#b91c1c")}
  {section("🧪 semgrep Static Analysis", semgrep_html, "#b45309")}
</div>
</body>
</html>"""

    report_path = out_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path


# ══════════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="JS Extractor v2 — extract, beautify, and analyze all JS from a web page",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Target
    parser.add_argument("url", help="Target page URL")

    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--cookie", default="", metavar="STR",
        help='Cookie string, e.g. "session=abc; token=xyz"')
    auth.add_argument("--jwt", default="", metavar="TOKEN",
        help="JWT token (Bearer prefix optional)")
    auth.add_argument("--header", action="append", metavar="KEY:VAL",
        help="Custom header (repeatable)")

    # Extraction
    ext = parser.add_argument_group("Extraction")
    ext.add_argument("--dynamic", action="store_true",
        help="Use headless Chromium to capture dynamically loaded scripts")
    ext.add_argument("--katana", action="store_true",
        help="Deep-crawl the site with katana (must be installed) to discover JS files beyond the single page")
    ext.add_argument("--katana-depth", type=int, default=2, metavar="N",
        help="Crawl depth for --katana (default: 2)")
    ext.add_argument("--gau", action="store_true",
        help="Pull historical URLs for the target domain via gau (Wayback/OTX/CommonCrawl/URLScan), "
             "then feed discovered .js URLs into extraction (must be installed)")
    ext.add_argument("--gau-providers", default="", metavar="LIST",
        help="Comma-separated gau providers, e.g. 'wayback,otx' (default: all)")
    ext.add_argument("--httpx-probe", action="store_true",
        help="Probe --gau results with httpx to keep only URLs that are alive today "
             "(must be installed; without this flag, gau results are used unfiltered)")
    ext.add_argument("--no-inline", action="store_true",
        help="Skip inline <script> blocks")
    ext.add_argument("--no-external", action="store_true",
        help="Skip external .js files")
    ext.add_argument("--no-workers", action="store_true",
        help="Skip Web Worker and Service Worker scripts")
    ext.add_argument("--no-sourcemaps", action="store_true",
        help="Skip source map recovery")
    ext.add_argument("--no-imports", action="store_true",
        help="Skip following import/require chains")

    # Analysis
    ana = parser.add_argument_group("Analysis")
    ana.add_argument("--endpoints", action="store_true",
        help="Extract API endpoints (includes hidden/internal detection)")
    ana.add_argument("--params", action="store_true",
        help="Extract parameters for fuzzing; saves params.txt wordlist")
    ana.add_argument("--secrets", action="store_true",
        help="Scan for leaked keys, tokens, passwords")
    ana.add_argument("--cve", action="store_true",
        help="Fingerprint library versions in the JS and check OSV.dev for known CVEs")
    ana.add_argument("--wappalyzer", action="store_true",
        help="Run wappalyzer CLI for overall tech-stack fingerprinting (requires: npm install -g wappalyzer)")
    ana.add_argument("--retire", action="store_true",
        help="Run retire.js against downloaded JS for local signature-based CVE scanning (requires: npm install -g retire)")
    ana.add_argument("--semgrep", action="store_true",
        help="Run semgrep static analysis on downloaded JS (requires: pip install semgrep)")
    ana.add_argument("--semgrep-config", action="append", metavar="RULESET",
        help="Semgrep config/ruleset, repeatable (default: p/xss and p/javascript)")
    ana.add_argument("--linkfinder", action="store_true",
        help="Run LinkFinder against downloaded JS for endpoint extraction (needs LinkFinder installed separately)")
    ana.add_argument("--linkfinder-path", default="", metavar="PATH",
        help="Path to linkfinder.py if it's not on PATH as 'linkfinder'")
    ana.add_argument("--all-analysis", action="store_true",
        help="Enable --endpoints, --params, --secrets, --cve, --wappalyzer, --retire, --semgrep, and --linkfinder together")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--output-dir", default="./js_output", metavar="DIR",
        help="Output directory (default: ./js_output)")
    out.add_argument("--merge", action="store_true",
        help="Combine all scripts into ALL_SCRIPTS_MERGED.js")
    out.add_argument("--report", action="store_true",
        help="Generate an HTML analysis report")

    args = parser.parse_args()

    # --all-analysis shortcut
    if args.all_analysis:
        args.endpoints = args.params = args.secrets = args.cve = True
        args.wappalyzer = args.retire = args.semgrep = args.linkfinder = True

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update(build_headers(args))
    session.cookies.update(build_cookies(args))

    # ── Step 1: Fetch the page ────────────────────────────────────────────────
    print(f"\n{bold('[*]')} Target: {cyan(args.url)}\n")
    resp = fetch(args.url, session)
    if not resp:
        sys.exit(1)
    base_html = resp.text

    # Tech-stack fingerprinting (independent of JS extraction, so run it first)
    wappalyzer_techs = []
    if args.wappalyzer:
        print(f"{bold('[*]')} Tech-stack fingerprinting...")
        wappalyzer_techs = run_wappalyzer(args.url)
        if wappalyzer_techs:
            for t in wappalyzer_techs:
                cats = f" [{', '.join(t['categories'])}]" if t["categories"] else ""
                ver = f" v{t['version']}" if t["version"] else ""
                print(f"    - {t['name']}{ver}{cats}")
        print()

    # ── Step 2: Collect script URLs ───────────────────────────────────────────
    static_ext, static_inline = extract_from_html(base_html, args.url)

    if args.dynamic:
        dynamic_ext, dynamic_inline = extract_dynamic(args.url, args)
        # Merge: static first, then any new URLs/blocks from dynamic pass
        all_ext_urls = list(dict.fromkeys(static_ext + dynamic_ext))
        all_inline   = static_inline + [b for b in dynamic_inline if b not in static_inline]
    else:
        all_ext_urls = static_ext
        all_inline   = static_inline

    if args.katana:
        katana_js = run_katana(
            args.url,
            depth=args.katana_depth,
            headers=build_headers(args),
            cookies=build_cookies(args),
        )
        all_ext_urls = list(dict.fromkeys(all_ext_urls + katana_js))

    # ── gau: historical URL collection, optionally filtered through httpx ─────
    if args.gau:
        domain = urlparse(args.url).hostname
        providers = [p.strip() for p in args.gau_providers.split(",") if p.strip()] or None
        gau_urls = run_gau(domain, providers=providers)

        if gau_urls:
            if args.httpx_probe:
                alive = run_httpx_probe(
                    gau_urls,
                    headers=build_headers(args),
                    cookies=build_cookies(args),
                )
                alive_path = output_dir / "gau_alive.txt"
                with alive_path.open("w", encoding="utf-8") as f:
                    for r in alive:
                        f.write(f"{r.get('status_code', '?')}  {r.get('url', '')}\n")
                print(f"  Saved -> {alive_path}")
                usable_urls = [r["url"] for r in alive if r.get("url")]
            else:
                gau_all_path = output_dir / "gau_all.txt"
                gau_all_path.write_text("\n".join(gau_urls), encoding="utf-8")
                print(f"  Saved -> {gau_all_path}")
                usable_urls = gau_urls

            gau_js = sorted(set(u for u in usable_urls if u.split("?")[0].endswith(".js")))
            print(f"  {green('[gau]')} {len(gau_js)} JS file(s) from gau results queued for extraction")
            all_ext_urls = list(dict.fromkeys(all_ext_urls + gau_js))

    print(f"{bold('[*]')} Discovered: {len(all_ext_urls)} external script(s), {len(all_inline)} inline block(s)\n")

    # Accumulate all JS text for analysis and optional merge
    all_js_text = ""
    all_contents_merge = []
    file_records = []         # for report
    workers_to_fetch = set()
    imports_to_fetch = set()

    # ── Step 3: Download & beautify external scripts ──────────────────────────
    if not args.no_external:
        ext_dir = output_dir / "external"
        seen = set()
        queue = list(all_ext_urls)

        while queue:
            src_url = queue.pop(0)
            if src_url in seen:
                continue
            seen.add(src_url)

            print(f"  {cyan('[DL]')} {src_url}")
            js_resp = fetch(src_url, session)
            if not js_resp:
                continue

            raw = js_resp.text
            print(f"       Beautifying ({len(raw):,} chars)...")
            beautified = beautify(raw)
            all_js_text += beautified + "\n"

            fname = safe_filename(src_url, prefix=f"ext_{len(seen):03d}")
            fpath = ext_dir / fname
            save_js(beautified, fpath, url=src_url)

            size_kb = fpath.stat().st_size / 1024
            file_records.append({"kind": "external", "filename": fname,
                                  "url": src_url, "saved_path": str(fpath.relative_to(output_dir)),
                                  "size_kb": size_kb})

            # Source map recovery
            if not args.no_sourcemaps:
                try_recover_sourcemap(raw, src_url, session, output_dir)

            # Follow imports
            if not args.no_imports:
                for imp_url in find_js_imports(raw, src_url):
                    if imp_url not in seen:
                        queue.append(imp_url)
                        imports_to_fetch.add(imp_url)

            # Find workers
            if not args.no_workers:
                for w_url in find_workers(raw, src_url):
                    if w_url not in seen:
                        workers_to_fetch.add(w_url)
                        queue.append(w_url)

            if all_contents_merge is not None:
                all_contents_merge.append(
                    f"\n\n{'='*70}\n// FILE: {fname}\n// SOURCE: {src_url}\n{'='*70}\n\n"
                    + beautified
                )

            time.sleep(0.15)  # polite pacing

    # ── Step 4: Inline script blocks ──────────────────────────────────────────
    if not args.no_inline and all_inline:
        inline_dir = output_dir / "inline"
        print(f"\n{bold('[*]')} Saving {len(all_inline)} inline block(s)...")
        for i, code in enumerate(all_inline, 1):
            beautified = beautify(code)
            all_js_text += beautified + "\n"
            fname = f"inline_{i:03d}.js"
            fpath = inline_dir / fname
            save_js(beautified, fpath)
            size_kb = fpath.stat().st_size / 1024
            file_records.append({"kind": "inline", "filename": fname,
                                  "url": f"{args.url}#inline-{i}", "saved_path": str(fpath.relative_to(output_dir)),
                                  "size_kb": size_kb})
            all_contents_merge.append(
                f"\n\n{'='*70}\n// INLINE BLOCK {i}\n{'='*70}\n\n" + beautified
            )

    # ── Step 5: Merge ─────────────────────────────────────────────────────────
    if args.merge and all_contents_merge:
        merged_path = output_dir / "ALL_SCRIPTS_MERGED.js"
        banner = (
            f"/* {'='*66}\n"
            f"   Merged JS dump\n"
            f"   Source: {args.url}\n"
            f"   Sections: {len(all_contents_merge)}\n"
            f"   {'='*66} */\n"
        )
        merged_path.write_text(banner + "".join(all_contents_merge), encoding="utf-8")
        print(f"\n{green('[*]')} Merged -> {merged_path}")

    # ══════════════════════════════════════════════════════════════════════════
    # Analysis phase
    # ══════════════════════════════════════════════════════════════════════════

    report_data = {
        "target_url": args.url,
        "total_files": len(file_records),
        "total_size_kb": sum(f["size_kb"] for f in file_records),
        "files": file_records,
        "technologies": wappalyzer_techs,
    }

    # Framework detection (always runs if we have JS)
    frameworks = detect_frameworks(all_js_text) if all_js_text else []
    report_data["frameworks"] = frameworks
    if frameworks:
        print(f"\n{bold('[Framework]')} Detected: {', '.join(yellow(f) for f in frameworks)}")

    # Endpoints
    report_data["endpoints"] = []
    report_data["hidden_endpoints"] = []
    if args.endpoints and all_js_text:
        print(f"\n{bold('[Endpoints]')} Scanning...")
        endpoints, hidden = extract_endpoints(all_js_text)
        report_data["endpoints"] = endpoints
        report_data["hidden_endpoints"] = hidden

        ep_path = output_dir / "endpoints.txt"
        ep_path.write_text("\n".join(endpoints), encoding="utf-8")
        hidden_path = output_dir / "endpoints_hidden.txt"
        hidden_path.write_text("\n".join(hidden), encoding="utf-8")

        print(f"  Found {green(str(len(endpoints)))} endpoint(s)  ({red(str(len(hidden)))} flagged as hidden/internal)")
        if hidden:
            print(f"  {red('[!] Hidden/Internal endpoints:')}")
            for h in hidden:
                print(f"      {red(h)}")
        print(f"  Saved -> {ep_path}")
        print(f"  Saved -> {hidden_path}")

    # Parameters
    report_data["params"] = []
    report_data["wordlist_path"] = ""
    if args.params and all_js_text:
        print(f"\n{bold('[Params]')} Extracting for fuzzing...")
        params = extract_params(all_js_text, base_html)
        report_data["params"] = params

        wordlist_path = output_dir / "params_wordlist.txt"
        wordlist_path.write_text("\n".join(params), encoding="utf-8")
        report_data["wordlist_path"] = str(wordlist_path)

        print(f"  Found {green(str(len(params)))} unique parameter(s)")
        print(f"  Wordlist -> {wordlist_path}")

    # Secrets
    report_data["secrets"] = []
    if args.secrets and all_js_text:
        print(f"\n{bold('[Secrets]')} Scanning for leaked credentials...")
        secrets = find_secrets(all_js_text)
        report_data["secrets"] = secrets
        if secrets:
            print(f"  {red(f'[!] {len(secrets)} potential secret(s) found:')}")
            for s in secrets:
                masked = s["value"][:6] + "..." + s["value"][-4:]
                print(f"      {red('[' + s['type'] + ']')} {masked}  (line {s['line']})")
        else:
            print(f"  {green('No secrets detected.')}")

    # Library versions + CVE matching
    report_data["libraries"] = []
    report_data["cves"] = []
    if args.cve and all_js_text:
        print(f"\n{bold('[CVE]')} Fingerprinting library versions...")
        libs = detect_library_versions(all_js_text)
        report_data["libraries"] = libs

        if not libs:
            print(f"  No version-fingerprinted libraries detected "
                  f"(minified bundles often strip the banner comments this relies on).")
        else:
            print(f"  Detected {green(str(len(libs)))} version-fingerprinted librar{'y' if len(libs) == 1 else 'ies'}:")
            for l in libs:
                print(f"    - {l['name']} v{l['version']}")

            print(f"  {bold('[CVE]')} Querying OSV.dev for known vulnerabilities...")
            cves = lookup_cves(libs)
            report_data["cves"] = cves

            cve_path = output_dir / "cve_report.txt"
            with cve_path.open("w", encoding="utf-8") as f:
                for c in cves:
                    label = c["cve"] or c["id"]
                    f.write(f"{c['library']}@{c['version']}  {label}  "
                            f"(severity: {c['severity'] or 'n/a'})\n"
                            f"  {c['summary']}\n  {c['url']}\n\n")

            if cves:
                plural = "y" if len(cves) == 1 else "ies"
                print(f"  {red(f'[!] {len(cves)} known vulnerabilit{plural} found:')}")
                for c in cves:
                    label = c["cve"] or c["id"]
                    print(f"      {red(label)} - {c['library']}@{c['version']} - {c['summary'][:80]}")
            else:
                print(f"  {green('No known CVEs found for the detected versions.')}")
            print(f"  Saved -> {cve_path}")

    # retire.js — local signature-based CVE scan of the downloaded external JS
    report_data["retire_findings"] = []
    if args.retire:
        print(f"\n{bold('[retire.js]')} Scanning downloaded JS for known-vulnerable components...")
        retire_findings = run_retire(output_dir / "external")
        report_data["retire_findings"] = retire_findings
        if retire_findings:
            retire_path = output_dir / "retire_report.txt"
            with retire_path.open("w", encoding="utf-8") as f:
                for r in retire_findings:
                    f.write(f"{r['file']}  ->  {r['component']}@{r['version']}\n")
                    for v in r["vulnerabilities"]:
                        ids = v.get("identifiers", {})
                        cve = ids.get("CVE", [ids.get("summary", "")])
                        f.write(f"    [{v.get('severity', 'n/a')}] {', '.join(cve) if isinstance(cve, list) else cve}\n")
                    f.write("\n")
            print(f"  Saved -> {retire_path}")

    # semgrep — static analysis for dangerous client-side patterns
    report_data["semgrep_findings"] = []
    if args.semgrep:
        print(f"\n{bold('[semgrep]')} Running static analysis...")
        semgrep_findings = run_semgrep(output_dir / "external", configs=args.semgrep_config)
        report_data["semgrep_findings"] = semgrep_findings
        if semgrep_findings:
            semgrep_path = output_dir / "semgrep_report.txt"
            with semgrep_path.open("w", encoding="utf-8") as f:
                for s in semgrep_findings:
                    f.write(f"[{s['severity']}] {s['rule_id']}\n  {s['file']}:{s['line']}\n  {s['message']}\n\n")
            for s in semgrep_findings[:10]:
                print(f"    {red('[' + s['severity'] + ']')} {s['rule_id']} — {s['file']}:{s['line']}")
            print(f"  Saved -> {semgrep_path}")

    # LinkFinder — supplemental endpoint extraction
    report_data["linkfinder_endpoints"] = []
    if args.linkfinder:
        print(f"\n{bold('[LinkFinder]')} Extracting endpoints from downloaded JS...")
        lf_endpoints = run_linkfinder(output_dir / "external", linkfinder_path=args.linkfinder_path)
        report_data["linkfinder_endpoints"] = lf_endpoints
        if lf_endpoints:
            lf_path = output_dir / "linkfinder_endpoints.txt"
            lf_path.write_text("\n".join(lf_endpoints), encoding="utf-8")
            print(f"  Saved -> {lf_path}")

    # HTML report
    if args.report:
        rpath = generate_report(report_data, output_dir)
        print(f"\n{green('[Report]')} HTML report -> {rpath}")

    # ── Summary ───────────────────────────────────────────────────────────────
    js_files = list(output_dir.rglob("*.js"))
    total_kb = sum(f.stat().st_size for f in js_files) / 1024
    print(f"\n{'─'*55}")
    print(f"{green('[+]')} Done — {len(js_files)} JS file(s), {total_kb:.1f} KB total")
    print(f"    Output dir: {output_dir.resolve()}")
    print(f"{'─'*55}")
    print(f"{cyan('[Manual step]')} Live source→sink tracing (DOM Invader in Burp Suite) "
          f"isn't automatable — load {args.url} in a Burp-proxied browser with DOM Invader "
          f"enabled and use the beautified JS + endpoints/params above as your map.\n")


if __name__ == "__main__":
    main()
