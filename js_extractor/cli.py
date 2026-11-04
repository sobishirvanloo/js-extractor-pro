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
import bisect
import contextlib
import fnmatch
import ipaddress
import hashlib
import json
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
from collections import defaultdict
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
import jsbeautifier

# Optional — only needed for --dynamic
try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False


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
    """Generic (non-sensitive) request headers sent to every host."""
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }


def build_auth_headers(args) -> dict:
    """
    User-supplied headers (--jwt and every --header). These may carry
    credentials, so they are only ever sent to the target host — see
    ScopedAuth.
    """
    headers = {}
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


# Second-level labels that form a public suffix together with a 2-letter
# ccTLD (example.co.uk, example.com.au, example.ac.ir, ...). A heuristic —
# no public-suffix list dependency; use --include-host for edge cases.
_SLD_SUFFIXES = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go",
                 "gob", "gv", "mil", "nic", "ltd", "plc", "sch", "id", "info"}


def base_domain(host: str) -> str:
    """Approximate registrable domain: app.example.co.uk -> example.co.uk."""
    host = (host or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host                                 # IPs have no parent domain
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_in_domain(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


class Scope:
    """
    Which hosts the tool may send ANY request to (--scope):
      any    — everything (default, previous behaviour)
      domain — the target's registrable domain and all its subdomains
      host   — the exact target host only
    --include-host adds hosts (glob) to host/domain modes; --exclude-host
    (glob) always wins. The target URL itself is always allowed.
    """

    MODES = ("any", "domain", "host")

    def __init__(self, target_url: str, mode: str = "any", include=(), exclude=()):
        self.host = (urlparse(target_url).hostname or "").lower()
        self.domain = base_domain(self.host)
        self.mode = mode
        self.include = [p.lower() for p in (include or [])]
        self.exclude = [p.lower() for p in (exclude or [])]

    @property
    def restricted(self) -> bool:
        return self.mode != "any" or bool(self.exclude)

    def allows(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if any(fnmatch.fnmatchcase(host, p) for p in self.exclude):
            return False
        if self.mode == "any" or host == self.host:
            return True
        if any(fnmatch.fnmatchcase(host, p) for p in self.include):
            return True
        return self.mode == "domain" and host_in_domain(host, self.domain)

    def describe(self) -> str:
        what = {"any": "any host", "domain": f"*.{self.domain}", "host": self.host}[self.mode]
        extra = "".join(f" +{p}" for p in self.include) + "".join(f" -{p}" for p in self.exclude)
        return what + extra


class ScopedAuth(requests.auth.AuthBase):
    """
    Attach the user's auth headers / cookies only to requests for the target
    (never downgrading https -> http). Everything else — CDNs, analytics,
    cross-origin imports, source maps, gau URLs — is fetched without
    credentials. mode (--auth-scope):
      host   — exact target host only (default)
      domain — target's registrable domain and its subdomains (for apps
               split across app./api./auth. that share a session)
    """

    def __init__(self, target_url: str, headers: dict, cookies: dict, mode: str = "host"):
        parsed = urlparse(target_url)
        self.host = (parsed.hostname or "").lower()
        self.domain = base_domain(self.host)
        self.mode = mode
        self.scheme = parsed.scheme.lower()
        self.headers = dict(headers or {})
        self.cookie_str = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())

    def in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if self.mode == "domain":
            if not host_in_domain(host, self.domain):
                return False
        elif host != self.host:
            return False
        if self.scheme == "https" and parsed.scheme.lower() != "https":
            return False
        return True

    def __call__(self, r):
        if self.in_scope(r.url):
            r.headers.update(self.headers)
            if self.cookie_str:
                existing = r.headers.get("Cookie")
                r.headers["Cookie"] = f"{existing}; {self.cookie_str}" if existing else self.cookie_str
        return r


MAX_REDIRECTS = 10


class RateLimiter:
    """
    Global requests-per-second cap shared by every download thread (a simple
    scheduled-slot limiter: each request reserves the next free slot).
    rate <= 0 disables it.
    """

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        if slot > now:
            time.sleep(slot - now)


def make_session(args, scope, limiter=None, max_bytes=0, cookies=None) -> requests.Session:
    """
    Build a configured Session (headers, scoped auth, scope, proxy, TLS,
    rate limit, size cap). requests.Session isn't guaranteed thread-safe, so
    each download thread gets its own; `cookies` seeds it with cookies the
    target set on the main session (WAF/session cookies some sites require).
    """
    s = requests.Session()
    s.headers.update(build_headers(args))
    # Credentials go only to the auth scope (see ScopedAuth)
    s.auth = ScopedAuth(args.url, build_auth_headers(args), build_cookies(args),
                        mode=getattr(args, "auth_scope", "host"))
    s.scope = scope                       # enforced in fetch(), per redirect hop
    s.limiter = limiter
    s.max_bytes = max_bytes
    if getattr(args, "proxy", None):
        s.proxies = {"http": args.proxy, "https": args.proxy}
    if getattr(args, "insecure", False):
        s.verify = False
    elif getattr(args, "ca_cert", None):
        s.verify = args.ca_cert
    if cookies is not None:
        s.cookies.update(cookies)
    return s


def fetch(url: str, session: requests.Session, quiet: bool = False):
    """
    GET a URL. Returns Response or None on failure; on failure
    session.fetch_error holds a short reason ("out_of_scope", "too_large",
    "tls", "proxy", "error").

    Redirects are followed manually so that session.auth (ScopedAuth) and
    session.scope (Scope) are re-evaluated for every hop; with requests'
    built-in redirect handling, custom headers would be carried over to a
    redirect target on another host, and redirects could leave the scope.
    Every hop also waits on the shared rate limiter, and bodies are streamed
    so session.max_bytes can abort oversized downloads early.
    """
    scope = getattr(session, "scope", None)
    limiter = getattr(session, "limiter", None)
    max_bytes = getattr(session, "max_bytes", 0) or 0
    session.fetch_error = None
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if scope is not None and not scope.allows(url):
                session.fetch_error = "out_of_scope"
                if not quiet:
                    print(f"  {yellow('[SKIP]')} Out of scope ({scope.describe()}): {url}")
                return None
            if limiter is not None:
                limiter.wait()
            resp = session.get(url, timeout=20, allow_redirects=False, stream=True)
            if resp.is_redirect:
                resp.close()
                url = urljoin(resp.url, resp.headers["Location"])
                continue
            try:
                resp.raise_for_status()
            except requests.exceptions.HTTPError:
                resp.close()
                raise
            if max_bytes:
                declared = resp.headers.get("Content-Length", "")
                if declared.isdigit() and int(declared) > max_bytes:
                    resp.close()
                    return _too_large(session, url, int(declared), max_bytes, quiet)
                body = bytearray()
                for chunk in resp.iter_content(65536):
                    body += chunk
                    if len(body) > max_bytes:
                        resp.close()
                        return _too_large(session, url, len(body), max_bytes, quiet, partial=True)
                resp._content = bytes(body)          # pre-load so .text/.content work
            else:
                resp.content                          # read the whole body
            return resp
        raise requests.exceptions.TooManyRedirects(f"Exceeded {MAX_REDIRECTS} redirects")
    except requests.exceptions.SSLError as e:
        session.fetch_error = "tls"
        if not quiet:
            print(f"  {yellow('[WARN]')} TLS verification failed for {url}: {e}\n"
                  f"         Self-signed/internal CA or intercepting proxy? "
                  f"Use --ca-cert PATH or --insecure.", file=sys.stderr)
        return None
    except requests.exceptions.ProxyError as e:
        session.fetch_error = "proxy"
        if not quiet:
            print(f"  {yellow('[WARN]')} Proxy error fetching {url}: {e}\n"
                  f"         Is the proxy running and reachable?", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        session.fetch_error = "error"
        if not quiet:
            print(f"  {yellow('[WARN]')} Could not fetch {url}: {e}", file=sys.stderr)
        return None


def _too_large(session, url, size, limit, quiet, partial=False):
    session.fetch_error = "too_large"
    if not quiet:
        size_txt = f">{limit / 1048576:.0f}" if partial else f"{size / 1048576:.1f}"
        print(f"  {yellow('[SKIP]')} {url} is {size_txt} MB, over --max-size "
              f"{limit / 1048576:.0f} MB", file=sys.stderr)
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

    # <base href> changes how every relative URL on the page resolves
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_url = resolve(base_tag["href"], base_url) or base_url

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

    # Scripts the page only preloads (Vite emits modulepreload for every
    # chunk of the entry; Next/webpack use preload/prefetch as=script).
    for tag in soup.find_all("link", href=True):
        rel = {r.lower() for r in (tag.get("rel") or [])}
        is_script = (tag.get("as") or "").lower() == "script"
        if "modulepreload" in rel or (is_script and rel & {"preload", "prefetch"}):
            url = resolve(tag["href"], base_url)
            if url:
                external_srcs.append(url)

    return list(dict.fromkeys(external_srcs)), inline_blocks


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

    proxy = getattr(args, "proxy", None)
    insecure = bool(getattr(args, "insecure", False))
    auth_mode = getattr(args, "auth_scope", "host") or "host"
    fetch_scope = Scope(url, getattr(args, "scope", "any") or "any",
                        getattr(args, "include_host", None), getattr(args, "exclude_host", None))

    # Auth headers are injected per-request (auth scope only) via a route
    # handler — NOT via extra_http_headers, which would send them everywhere.
    extra_headers = build_auth_headers(args)
    scope = ScopedAuth(url, extra_headers, {}, mode=auth_mode)

    # Cookies: host-only by default; with --auth-scope domain they're set on
    # the registrable domain so the browser sends them to its subdomains too.
    cookie_target = ({"domain": "." + scope.domain, "path": "/"} if auth_mode == "domain"
                     else {"url": url})
    pw_cookies = [
        {"name": k, "value": v, **cookie_target}
        for k, v in build_cookies(args).items()
    ]
    blocked = []

    # Any failure here (Chromium not installed, navigation error, page never
    # going network-idle, page crash) must not kill the whole run: whatever
    # was captured so far is returned and the static results still stand.
    try:
        with sync_playwright() as pw:
            launch_opts = {"headless": True}
            if proxy:
                launch_opts["proxy"] = {"server": proxy}
            browser = pw.chromium.launch(**launch_opts)
            try:
                # TLS errors are only ignored with --insecure (Chromium can't be
                # pointed at a CA file, so intercepting proxies need --insecure).
                context = browser.new_context(ignore_https_errors=insecure)
                if pw_cookies:
                    context.add_cookies(pw_cookies)
                if extra_headers or fetch_scope.restricted:
                    def route_handler(route, request):
                        # Out-of-scope requests never leave the browser
                        if not fetch_scope.allows(request.url) and request.url.startswith("http"):
                            blocked.append(request.url)
                            route.abort("blockedbyclient")
                        elif extra_headers and scope.in_scope(request.url):
                            route.continue_(headers={**request.headers, **extra_headers})
                        else:
                            route.continue_()
                    context.route("**/*", route_handler)

                page = context.new_page()

                # Intercept every network request ("request" also fires for
                # requests the route handler then aborts — skip those)
                def on_request(request):
                    if request.resource_type == "script" and fetch_scope.allows(request.url):
                        collected_urls.append(request.url)

                page.on("request", on_request)

                # SPAs with polling / websockets / analytics beacons often never
                # reach "networkidle". Wait for the load event first (hard
                # requirement), then give networkidle a bounded best-effort window.
                try:
                    page.goto(url, wait_until="load", timeout=30000)
                except PlaywrightTimeoutError:
                    print(f"  {yellow('[WARN]')} Page 'load' event not reached in 30s — using what loaded so far")
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except PlaywrightTimeoutError:
                    print(f"  {yellow('[WARN]')} Network never went idle (polling/websockets?) — continuing")

                # Extra time for late lazy-loaded chunks, while the request
                # listener is still active (the old sleep ran after collection).
                page.wait_for_timeout(2000)

                # Also grab inline scripts from the live DOM
                scripts = page.evaluate("""
                    () => Array.from(document.querySelectorAll('script:not([src])'))
                               .map(s => s.textContent)
                               .filter(t => t.trim().length > 0)
                """)
                inline_blocks.extend(s.strip() for s in scripts)
            finally:
                browser.close()
    except Exception as e:
        print(f"  {yellow('[WARN]')} Dynamic extraction failed ({type(e).__name__}: {str(e).splitlines()[0][:200] if str(e) else ''})"
              f" — continuing with {len(collected_urls)} script(s) captured so far")

    collected_urls = list(dict.fromkeys(collected_urls))
    if blocked:
        print(f"  {yellow('[Scope]')} Browser blocked {len(set(blocked))} out-of-scope request(s) "
              f"({fetch_scope.describe()})")
    print(cyan(f"  [Browser] Captured {len(collected_urls)} script request(s), {len(inline_blocks)} inline block(s)"))
    return collected_urls, inline_blocks


# ══════════════════════════════════════════════════════════════════════════════
# Import/require chain follower
# ══════════════════════════════════════════════════════════════════════════════

# Matches: import x from './chunk.js' | import x from "/assets/a.js" |
#          require('../util.js') | import('./lazy.mjs') | export * from './b.js'
_IMPORT_RE = re.compile(
    r'''(?:import\s+[^;'"`]*?from\s*|export\s+[^;'"`]*?from\s*|import\s+|require\s*\(\s*|import\s*\(\s*)'''
    r'''['"`]((?:\.{1,2})?/[^'"`\s]+\.m?js(?:\?[^'"`\s]*)?)['"`]''',
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
# Lazy chunk discovery (webpack / Next.js / Vite)
# ══════════════════════════════════════════════════════════════════════════════
#
# Bundlers split SPAs into dozens or hundreds of lazily loaded chunks that no
# <script> tag ever references — they are requested only when the user
# navigates to the matching route. Their URLs are, however, fully described
# by data inside the shipped JS:
#   webpack 4/5 (CRA, Angular CLI, Next, Vue CLI, ...): a runtime function
#     (`__webpack_require__.u` / `jsonpScriptSrc`) that builds a chunk URL
#     from the chunk id plus {id: name} / {id: contenthash} maps, prefixed
#     by the public path (`__webpack_require__.p`).
#   Next.js: _buildManifest.js maps every page route to its chunks.
#   Vite: preload dependency lists ("assets/About-1a2b3c.js") and, when
#     deployed publicly, .vite/manifest.json.

def _scan_js_expr(code: str, start: int, limit: int = 2_000_000) -> str:
    """
    Return the JS expression starting at `start`, up to the first top-level
    `;` `,` `}` or `)` (quote- and bracket-aware). Enough for the small,
    machine-generated expressions in webpack runtimes.
    """
    depth, i, end = 0, start, min(len(code), start + limit)
    while i < end:
        ch = code[i]
        if ch in "\"'`":
            j = i + 1
            while j < end and code[j] != ch:
                j += 2 if code[j] == "\\" else 1
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in ";," and depth == 0:
            break
        i += 1
    return code[start:i].strip()


def _split_top_level(expr: str, sep: str = "+") -> list[str]:
    parts, depth, cur, i = [], 0, [], 0
    while i < len(expr):
        ch = expr[i]
        if ch in "\"'`":
            j = i + 1
            while j < len(expr) and expr[j] != ch:
                j += 2 if expr[j] == "\\" else 1
            cur.append(expr[i:j + 1]); i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur).strip()); cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur).strip())
    return parts


def _strip_parens(term: str) -> str:
    """Remove parentheses that wrap the whole term: '((a))' -> 'a'."""
    while term.startswith("(") and term.endswith(")"):
        depth = 0
        for i, ch in enumerate(term):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(term) - 1:
                return term                       # '(a)+(b)' — not one wrapper
        term = term[1:-1].strip()
    return term


_JS_OBJ_ENTRY_RE = re.compile(
    r'''(?:(\d+)|"([^"]*)"|'([^']*)'|([A-Za-z_$][\w$]*))\s*:\s*(?:"([^"]*)"|'([^']*)')''')


def _parse_js_map(obj: str) -> dict:
    """Parse a flat {key: "string"} object literal as emitted by webpack."""
    out = {}
    for m in _JS_OBJ_ENTRY_RE.finditer(obj):
        key = next(g for g in m.groups()[:4] if g is not None)
        out[key] = m.group(5) if m.group(5) is not None else m.group(6)
    return out


class ChunkTemplate:
    """
    A webpack chunk-URL function compiled to a list of parts:
      ("lit", s) | ("id",) | ("p",) | ("map", {id: s}, fallback_to_id)
    """

    def __init__(self, parts, public_path, has_p, script_url, fixed=None):
        self.parts, self.public_path, self.has_p, self.script_url = parts, public_path, has_p, script_url
        self.fixed = fixed or {}        # id -> literal path, from `ID===e?"path":...` ternaries

    @property
    def known_ids(self) -> set:
        """Ids enumerated by a map without fallback (the contenthash map lists every chunk)."""
        ids = set(self.fixed)
        for p in self.parts:
            if p[0] == "map" and not p[2]:
                ids |= set(p[1])
        return ids

    def _absolute(self, path: str, page_url: str, prefixed: bool):
        if not prefixed:
            path = (self.public_path or "") + path
        # publicPath "" (webpack 4 default) is relative to the page; an
        # unknown/"auto" publicPath (webpack 5) is relative to the runtime script
        base = page_url if self.public_path == "" else self.script_url
        return resolve(path, base)

    def url_for(self, chunk_id: str, page_url: str):
        if chunk_id in self.fixed:
            return self._absolute(self.fixed[chunk_id], page_url, False)
        out = []
        for p in self.parts:
            if p[0] == "lit":
                out.append(p[1])
            elif p[0] == "id":
                out.append(chunk_id)
            elif p[0] == "p":
                out.append(self.public_path or "")
            else:                                   # map lookup
                val = p[1].get(chunk_id)
                if val is None:
                    if not p[2]:
                        return None                 # no hash for this id → not a chunk
                    val = chunk_id
                out.append(val)
        return self._absolute("".join(out), page_url, self.has_p)


_CHUNK_FN_RES = [
    # webpack 5:  r.u = e => "static/js/" + e + ".js"   |   r.u = function(e){ return ... }
    # (minifiers drop the space: `return"static/js/"+e`)
    # The (?<![\w$]) anchor matters: without it `[\w$]+` is retried from every
    # position inside long identifiers/strings → O(n²) on multi-MB bundles.
    re.compile(r'''(?<![\w$])([\w$]{1,64})\.u\s*=\s*(?:function\s*\(\s*([\w$]+)\s*\)\s*\{\s*return(?![\w$])\s*'''
               r'''|\(?\s*([\w$]+)\s*\)?\s*=>\s*(?:\{\s*return(?![\w$])\s*|\(?))'''),
    # webpack 4:  function jsonpScriptSrc(chunkId) { return __webpack_require__.p + ... }
    re.compile(r'''function\s+jsonpScriptSrc\s*\(\s*([\w$]+)\s*\)\s*\{\s*return(?![\w$])\s*()'''),
]
_CHUNK_ID_RE = re.compile(r'''(?<![\w$])[\w$]{1,40}\.e\(\s*(\d+|"[^"\\]{1,200}"|'[^'\\]{1,200}')\s*\)''')


MAX_CHUNK_FN_CANDIDATES = 10     # a real bundle has 1-2 runtimes; bounds hostile input


def find_chunk_templates(js_code: str, script_url: str) -> list[ChunkTemplate]:
    """Compile every webpack chunk-URL function found in this script."""
    templates, tried, public_paths = [], 0, {}
    for rx in _CHUNK_FN_RES:
        for m in rx.finditer(js_code):
            tried += 1
            if tried > MAX_CHUNK_FN_CANDIDATES:
                return templates
            if rx is _CHUNK_FN_RES[0]:
                obj, param = m.group(1), m.group(2) or m.group(3)
            else:
                obj, param = "__webpack_require__", m.group(1)
            if not param:
                continue
            # Ternary chains need the whole `a ? b : c` — scan with ':' and '?'
            # allowed, then peel off `ID===e?"literal":` (or `e===ID?...`) prefixes.
            expr = _scan_js_expr(js_code, m.end())
            fixed, p = {}, re.escape(param)
            tern = re.compile(r'''\s*(?:(\d+|"[^"]*"|'[^']*')\s*===?\s*''' + p + r'''|''' + p
                              + r'''\s*===?\s*(\d+|"[^"]*"|'[^']*'))\s*\?\s*("[^"]*"|'[^']*')\s*:\s*''')
            while True:
                t = tern.match(expr)
                if not t:
                    break
                fixed[(t.group(1) or t.group(2)).strip("\"'")] = t.group(3)[1:-1]
                expr = expr[t.end():]
            parts, has_p = [], False
            for term in _split_top_level(expr):
                term = _strip_parens(term)
                lit = re.fullmatch(r'''"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)\'''', term)
                if lit:
                    parts.append(("lit", lit.group(1) if lit.group(1) is not None else lit.group(2)))
                elif term == param:
                    parts.append(("id",))
                elif re.fullmatch(r"[\w$]+\.p", term):
                    parts.append(("p",)); has_p = True
                else:
                    lk = re.fullmatch(r"\(?\s*(\{.*\})\s*\)?\s*\[\s*" + re.escape(param)
                                      + r"\s*\]\s*(\|\|\s*" + re.escape(param) + r")?", term, re.S)
                    if not lk:
                        parts = None
                        break                       # unsupported construct — skip this fn
                    parts.append(("map", _parse_js_map(lk.group(1)), bool(lk.group(2))))
            if not parts or not any(p[0] == "lit" and re.search(r"\.m?js(\?|$)", p[1]) for p in parts):
                continue                            # not a JS chunk-URL builder
            # Public path: `<obj>.p = "..."` in the same runtime (one scan per object name)
            if obj not in public_paths:
                pm = re.search(r'(?<![\w$])' + re.escape(obj) + r'''\.p\s*=\s*(["'])([^"'\n]{0,500})\1''', js_code)
                public_paths[obj] = pm.group(2) if pm else None
            public_path = public_paths[obj]
            templates.append(ChunkTemplate(parts, public_path, has_p, script_url, fixed))
    return templates


def find_chunk_ids(js_code: str) -> set:
    """Chunk ids from `__webpack_require__.e(id)` calls (`n.e(42)` minified)."""
    return {m.group(1).strip("\"'") for m in _CHUNK_ID_RE.finditer(js_code)}


# Vite preload deps / generic bundler asset paths: "assets/About-1a2b3c.js"
_ASSET_PATH_RE = re.compile(
    r'''["'`]((?:\.?/)?(?:[\w\-.]+/)*(?:assets|chunks|static/js|static/chunks|js|dist|build)/'''
    r'''[\w\-.~/@]+?\.m?js)["'`]''')


def find_asset_paths(js_code: str, script_url: str, page_url: str) -> list[str]:
    """
    Script paths that bundlers keep as plain strings (Vite's __vitePreload
    dependency arrays, chunk lists). Bare "assets/x.js" is relative to the
    site base (Vite default base "/"); "./x.js" to the script itself.
    """
    out = []
    origin_root = urljoin(page_url, "/")
    for m in _ASSET_PATH_RE.finditer(js_code):
        p = m.group(1)
        base = script_url if p.startswith("./") else origin_root
        url = resolve(p, base)
        if url:
            out.append(url)
    return out


def parse_next_build_manifest(js_code: str, manifest_url: str) -> tuple[list[str], list[str]]:
    """
    Next.js _buildManifest.js → (chunk URLs, page routes). Chunk paths are
    relative to the asset prefix, i.e. everything before "/static/" in the
    manifest URL (".../_next/").
    """
    if "__BUILD_MANIFEST" not in js_code:
        return [], []
    prefix = manifest_url.split("/static/")[0] + "/"
    chunks = [urljoin(prefix, p) for p in re.findall(r'''["'](static/[^"']+?\.js)["']''', js_code)]
    routes = sorted(set(re.findall(r'''["'](/[^"']*)["']\s*:\s*\[''', js_code)))
    return list(dict.fromkeys(chunks)), routes


def next_build_manifest_urls(html: str, script_urls: list[str], page_url: str) -> list[str]:
    """Candidate _buildManifest.js URLs from the buildId in __NEXT_DATA__ / script paths."""
    ids = set(re.findall(r'''"buildId"\s*:\s*"([\w\-]+)"''', html))
    prefix = urljoin(page_url, "/_next/")
    for u in script_urls:
        m = re.search(r"^(.*?/_next/)static/([\w\-]+)/_(?:build|ssg)Manifest\.js", u)
        if m:
            ids.add(m.group(2)); prefix = m.group(1)
        elif "/_next/static/" in u:
            prefix = u.split("/_next/static/")[0] + "/_next/"
    return [f"{prefix}static/{i}/_buildManifest.js" for i in sorted(ids)]


def parse_vite_manifest(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Vite manifest.json → (chunk URLs, original source paths)."""
    try:
        data = json.loads(text)
    except ValueError:
        return [], []
    if not isinstance(data, dict):
        return [], []
    files, sources = [], []
    for src, entry in data.items():
        if isinstance(entry, dict) and isinstance(entry.get("file"), str):
            sources.append(src)
            if re.search(r"\.m?js$", entry["file"]):
                files.append(urljoin(base_url, entry["file"]))
    return files, sources


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
    r'(?://|/\*)[#@]\s*sourceMappingURL=([^\s*]+)', re.MULTILINE
)

def safe_sourcemap_dest(src_file: str, sm_root: Path):
    """
    Map an attacker-controlled `sources` entry from a source map to a path
    strictly inside sm_root. Drops '', '.', '..' segments (both / and \\
    separators), sanitises each remaining segment, then verifies the resolved
    path is still under sm_root. Returns None if no safe path can be built.
    """
    parts = [p for p in re.split(r"[\\/]+", src_file) if p not in ("", ".", "..")]
    parts = [re.sub(r"[^\w.\-]", "_", p) for p in parts]
    parts = [p for p in parts if p.strip(".")]   # no segments made only of dots
    if not parts:
        return None
    dest = (sm_root / Path(*parts)).resolve()
    if dest == sm_root or not dest.is_relative_to(sm_root):
        return None
    return dest


def _decode_data_uri(uri: str):
    """Decode a data: URI (base64 or percent-encoded). Returns text or None."""
    try:
        meta, payload = uri[5:].split(",", 1)
        if meta.lower().endswith(";base64"):
            return base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", "replace")
        return urllib.parse.unquote(payload)
    except Exception:
        return None


def parse_sourcemap(map_text: str) -> list[tuple[str, object]]:
    """
    Parse a Source Map v3 document with the stdlib json module.

    Handles the XSSI prefix ( )]}' ), `sourceRoot`, and index maps
    (`sections`, recursively). Returns a list of (source_path, content)
    pairs — content is None when the map lists a source without embedding
    its `sourcesContent`.
    """
    text = map_text.lstrip("﻿")
    if text.startswith(")]}"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    data = json.loads(text)

    def walk(sm: dict, depth: int = 0) -> list:
        if not isinstance(sm, dict) or depth > 5:
            return []
        if isinstance(sm.get("sections"), list):
            out = []
            for sec in sm["sections"]:
                if isinstance(sec, dict) and isinstance(sec.get("map"), dict):
                    out += walk(sec["map"], depth + 1)
            return out
        sources = sm.get("sources") or []
        contents = sm.get("sourcesContent") or []
        root = sm.get("sourceRoot") or ""
        if not isinstance(root, str):
            root = ""
        out = []
        for i, src in enumerate(sources):
            if not isinstance(src, str):
                continue
            content = contents[i] if i < len(contents) else None
            if root and "://" not in src and not src.startswith("/"):
                src = root.rstrip("/") + "/" + src
            out.append((src, content if isinstance(content, str) else None))
        return out

    return walk(data)


def find_sourcemap_ref(js_code: str, headers=None):
    """
    Locate the source map reference for a script: the LAST sourceMappingURL
    comment (bundlers append it at the end; earlier ones may belong to
    concatenated files), else the SourceMap / X-SourceMap response header.
    """
    matches = _SOURCEMAP_REF_RE.findall(js_code)
    if matches:
        return matches[-1].strip()
    if headers:
        for h in ("SourceMap", "X-SourceMap"):
            if headers.get(h):
                return headers[h].strip()
    return None


# Third-party code inside recovered sources. Kept for retire.js / version
# fingerprinting (that's where vulnerable libs live) but excluded from
# endpoint / param / secret / semgrep / LinkFinder passes, where it is noise.
VENDOR_DIR_NAMES = ("node_modules", "bower_components", "jspm_packages")

# Text source types worth analysing among recovered files
SOURCE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".vue", ".svelte", ".html", ".htm", ".json", ".graphql", ".gql",
}


def is_vendor_path(path: Path, root: Path) -> bool:
    """True if `path` sits under a vendor dir (checked relative to root only)."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(p in VENDOR_DIR_NAMES for p in parts)


def analysis_dirs(output_dir: Path) -> list[Path]:
    """Every output folder holding code worth scanning with external tools."""
    dirs = [output_dir / "external", output_dir / "inline", output_dir / "sourcemap_recovered"]
    return [d for d in dirs if d.is_dir() and any(d.iterdir())]


def read_recovered_sources(paths: list[Path], sm_root: Path) -> tuple[list, str, int]:
    """
    Read source-map-recovered files written during this run.
    Returns (first_party_files, vendor_text, n_vendor) where
    first_party_files is a list of (path, text).
    """
    app, vendor = [], []
    for p in paths:
        if p.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if is_vendor_path(p, sm_root):
            vendor.append(text)
        else:
            app.append((p, text))
    return app, "\n".join(vendor), len(vendor)


def try_recover_sourcemap(js_code: str, js_url: str, session: requests.Session, out_dir: Path,
                          headers=None, guess: bool = True, written: list = None) -> int:
    """
    Recover original (pre-bundle) sources for one script.

    The map is located via the sourceMappingURL comment, the SourceMap /
    X-SourceMap header, or — if neither exists and guess=True — by trying
    <script URL>.map (production sites often strip the comment but leave the
    .map file deployed).

    Output for each script goes to its own folder so same-named sources from
    different bundles don't overwrite each other:
      sourcemap_recovered/<bundle>/<original/path/...>
      sourcemap_recovered/<bundle>/_sources.txt   (every path listed in the
                                                   map, even without content)
    Returns the number of source files written.
    """
    map_ref = find_sourcemap_ref(js_code, headers)
    guessed = False

    if map_ref and map_ref.startswith("data:"):
        map_text = _decode_data_uri(map_ref)
        map_origin = "inline data: URI"
        if map_text is None:
            print(f"    {yellow('[WARN]')} Could not decode inline source map in {js_url}")
            return 0
    else:
        if map_ref:
            map_url = resolve(map_ref, js_url)
        elif guess:
            map_url = js_url.split("#", 1)[0].split("?", 1)[0] + ".map"
            guessed = True
        else:
            return 0
        if not map_url:
            return 0
        if not guessed:
            print(f"    {cyan('[SourceMap]')} Fetching: {map_url}")
        resp = fetch(map_url, session, quiet=guessed)
        if not resp:
            return 0
        map_text = resp.text
        map_origin = map_url

    try:
        entries = parse_sourcemap(map_text)
    except (ValueError, TypeError, AttributeError) as e:
        # A guessed URL hitting a soft-404 HTML page is expected — stay quiet
        if not guessed:
            print(f"    {yellow('[WARN]')} Could not parse source map {map_origin}: {e}")
        return 0
    if not entries:
        return 0
    if guessed:
        print(f"    {cyan('[SourceMap]')} Found undeclared map: {map_origin}")

    bundle_name = safe_filename(js_url, prefix="map")[:-len(".js")]
    bundle_dir = out_dir / "sourcemap_recovered" / bundle_name
    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_root = bundle_dir.resolve()

    recovered, unsafe = 0, 0
    index_lines = [f"# script: {js_url}", f"# map:    {map_origin}", ""]
    for src_file, content in entries:
        dest = safe_sourcemap_dest(src_file, bundle_root)
        if dest is None:
            unsafe += 1
            index_lines.append(f"[unsafe-skipped] {src_file}")
            continue
        if content is None:
            index_lines.append(f"[no-content]     {src_file}")
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Original sources are already readable and may be .ts/.vue/.css,
            # so they're written as-is rather than run through the JS beautifier.
            dest.write_text(content, encoding="utf-8")
        except OSError as e:
            index_lines.append(f"[write-error]    {src_file}  ({e})")
            continue
        recovered += 1
        if written is not None:
            written.append(dest)
        index_lines.append(f"{dest.relative_to(bundle_root)}  <-  {src_file}")

    (bundle_dir / "_sources.txt").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    no_content = len(entries) - recovered - unsafe
    msg = f"Recovered {recovered}/{len(entries)} source file(s) → {bundle_dir}"
    if no_content:
        msg += f"  ({no_content} listed without content)"
    print(f"    {green('[SourceMap]')} {msg}")
    if unsafe:
        print(f"    {yellow('[WARN]')} Skipped {unsafe} source path(s) that tried to escape the output dir")
    return recovered


# ══════════════════════════════════════════════════════════════════════════════
# Katana integration (optional deep crawl for additional JS files)
# ══════════════════════════════════════════════════════════════════════════════

def run_line_tool(name: str, cmd: list[str], timeout: int, input_text: str = None):
    """
    Run a line-oriented CLI tool (katana, gau, httpx). On timeout the child is
    killed but everything it already printed is kept: subprocess attaches the
    partial output to TimeoutExpired (always as bytes), and an incomplete final
    line is dropped. Returns (lines, returncode, stderr) or None if the tool
    could not be started at all.
    """
    try:
        proc = subprocess.Popen(
            cmd, text=True, encoding="utf-8", errors="replace",
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except Exception as e:
        print(f"  {yellow('[WARN]')} {name} execution failed: {e}")
        return None

    try:
        out, err = proc.communicate(input_text, timeout=timeout)
        return [l.strip() for l in out.splitlines() if l.strip()], proc.returncode, err
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or b""
        try:
            # Documented pattern: kill, then communicate() again — it returns
            # everything the child wrote, including what was already buffered.
            proc.kill()
            out, _ = proc.communicate(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as kill_err:
            # Couldn't stop it (e.g. restricted sandbox): fall back to the
            # output captured up to the timeout and leave the child behind.
            print(f"  {yellow('[WARN]')} could not stop {name} (pid {proc.pid}): {kill_err}")
            out = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
    except Exception as e:
        print(f"  {yellow('[WARN]')} {name} execution failed: {e}")
        return None

    out = out or ""
    if out and not out.endswith("\n"):          # drop a half-written final line
        out = out.rsplit("\n", 1)[0] if "\n" in out else ""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    print(f"  {yellow('[WARN]')} {name} timed out after {timeout}s — keeping {len(lines)} "
          f"partial result line(s) (raise with --tool-timeout)")
    return lines, None, ""


def run_katana(url: str, depth: int = 2, headers: dict = None, cookies: dict = None,
                timeout: int = 180, scope_mode: str = "any", auth_mode: str = "host",
                proxy: str = None) -> list[str]:
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

    # katana's default field scope (rdn) covers the root domain and all its
    # subdomains, and it sends -H headers to every in-scope host. Narrow it
    # to the exact host for --scope host, and when credentials are supplied
    # with --auth-scope host (so they don't leak to sibling subdomains).
    if scope_mode == "host" or ((headers or cookies) and auth_mode == "host"):
        cmd += ["-fs", "fqdn"]
    if proxy:
        cmd += ["-proxy", proxy]

    # katana accepts repeated -H "Key: Value" for custom headers (auth, cookie, etc.)
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]

    print(f"  {cyan('[Katana]')} Crawling {url} (depth={depth})... this can take a while")
    res = run_line_tool("katana", cmd, timeout)
    if res is None:
        return []
    all_urls, rc, err = res
    if rc not in (0, None) and not all_urls:
        print(f"  {yellow('[WARN]')} katana exited with code {rc}: {err.strip()[:200]}")
        return []

    # katana's plain output mixes all discovered URLs, so filter to .js ourselves
    js_urls = sorted(set(u for u in all_urls if u.split("?")[0].endswith(".js")))
    print(f"  {green('[Katana]')} Discovered {len(js_urls)} additional JS file(s) via crawl")
    return js_urls


# ══════════════════════════════════════════════════════════════════════════════
# gau integration (historical URL collection: Wayback / OTX / CommonCrawl / URLScan)
# ══════════════════════════════════════════════════════════════════════════════

def run_gau(domain: str, providers: list[str] = None, timeout: int = 180,
            blacklist: str = "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,css",
            subs: bool = True) -> list[str]:
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

    # gau only queries public archives (not the target), so it is never sent
    # through --proxy. --subs is dropped for --scope host.
    cmd = ["gau"]
    if subs:
        cmd.append("--subs")
    if blacklist:
        cmd += ["--blacklist", blacklist]
    if providers:
        cmd += ["--providers", ",".join(providers)]
    cmd += [domain]

    print(f"  {cyan('[gau]')} Pulling historical URLs for {domain} (Wayback/OTX/CommonCrawl/URLScan)...")
    res = run_line_tool("gau", cmd, timeout)
    if res is None:
        return []
    lines, rc, err = res
    if rc not in (0, None) and not lines:
        print(f"  {yellow('[WARN]')} gau exited with code {rc}: {err.strip()[:200]}")
        return []

    urls = sorted(set(lines))
    print(f"  {green('[gau]')} Collected {len(urls)} historical URL(s)")
    return urls


def run_httpx_probe(urls: list[str], headers: dict = None, cookies: dict = None,
                     threads: int = 50, timeout: int = 300, target_url: str = "",
                     auth_mode: str = "host", proxy: str = None,
                     same_host_redirects: bool = False) -> list[dict]:
    """
    Probe URLs with httpx. Credentials (headers/cookies) are only used for
    URLs inside the auth scope; every other URL (other subdomains from
    gau --subs, third parties) is probed in a separate run without them.
    Callers filter `urls` by --scope beforehand; same_host_redirects stops
    httpx from following redirects off to other (possibly out-of-scope) hosts.
    """
    kw = {"threads": threads, "timeout": timeout, "proxy": proxy,
          "same_host_redirects": same_host_redirects}
    if not (headers or cookies) or not target_url:
        return _run_httpx(urls, headers, cookies, **kw)
    scope = ScopedAuth(target_url, {}, {}, mode=auth_mode)
    in_scope = [u for u in urls if scope.in_scope(u)]
    out_scope = [u for u in urls if not scope.in_scope(u)]
    return (_run_httpx(in_scope, headers, cookies, **kw)
            + _run_httpx(out_scope, None, None, **kw))


def _run_httpx(urls: list[str], headers: dict = None, cookies: dict = None,
               threads: int = 50, timeout: int = 300, proxy: str = None,
               same_host_redirects: bool = False) -> list[dict]:
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

    cmd = ["httpx", "-silent", "-json",
           "-follow-host-redirects" if same_host_redirects else "-follow-redirects",
           "-status-code", "-title", "-content-length", "-tech-detect",
           "-threads", str(threads)]
    if proxy:
        cmd += ["-http-proxy", proxy]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]

    print(f"  {cyan('[httpx]')} Probing {len(urls)} URL(s) for liveness...")
    res = run_line_tool("httpx", cmd, timeout, input_text="\n".join(urls))
    if res is None:
        return []

    results = []
    for line in res[0]:
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
# Matching is case-insensitive, so normalise once (mixed-case entries like
# "toString" / "forEach" never matched before).
_PARAM_NOISE = {w.lower() for w in _PARAM_NOISE}

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

    Returns list of { type, value, line } dicts (line is 1-based within js_code).
    """
    # Offsets of every newline, so each match's line is a binary search
    # instead of re-counting the whole prefix (quadratic on big bundles).
    newlines = [i for i, ch in enumerate(js_code) if ch == "\n"]
    results = []
    seen = set()

    for pat, label in _SECRET_PATTERNS:
        for m in re.finditer(pat, js_code, re.IGNORECASE | re.MULTILINE):
            val = m.group(1)
            # Dedupe on the full value: a 30-char prefix collapsed distinct
            # JWTs, which all share the same encoded header.
            key = (label, val)
            if key in seen:
                continue
            seen.add(key)
            line_no = bisect.bisect_left(newlines, m.start()) + 1
            results.append({"type": label, "value": val, "line": line_no})

    return results


def find_secrets_in_files(files: list[tuple[str, str, int]]) -> list[dict]:
    """
    Run find_secrets() per file so every finding points at a real file and
    line on disk. `files` is a list of (display_path, text, header_lines),
    where header_lines is how many lines save_js() prepended on disk.

    The same secret often appears in several places (the minified bundle AND
    its recovered original source), so findings are grouped by (type, value):
      { type, value, file, line, locations: [{file, line}, ...] }
    with file/line being the first location.
    """
    grouped = {}
    for path, text, offset in files:
        for f in find_secrets(text):
            loc = {"file": path, "line": f["line"] + offset}
            key = (f["type"], f["value"])
            if key not in grouped:
                grouped[key] = {"type": f["type"], "value": f["value"], **loc, "locations": []}
            grouped[key]["locations"].append(loc)
    return list(grouped.values())


def mask_secret(val: str) -> str:
    """Show only a small prefix/suffix of a secret; never most of a short one."""
    n = len(val)
    head, tail = min(6, n // 4), min(4, n // 6)
    return val[:head] + "..." + (val[-tail:] if tail else "")


# ══════════════════════════════════════════════════════════════════════════════
# Analysis: DOM XSS sinks / sources / postMessage
# ══════════════════════════════════════════════════════════════════════════════
#
# A static map for DOM XSS hunting (and for driving DOM Invader): every place
# attacker-influenced data could reach an HTML/code/navigation sink, ranked by
# how directly a known source flows into it. Regex-based, so it's a triage
# list, not proof: "high" = a source appears in the sink's own argument.

# (label, regex ending right where the interesting argument starts, kind, mode)
#   mode: "rhs" = assignment value | int n = n-th call argument | "expr" = expression at match end
_DOM_SINKS = [
    ("innerHTML",                r'''\.(?:inner|outer)HTML\s*\+?=(?!=)\s*''', "html", "rhs"),
    ("insertAdjacentHTML",       r'''\.insertAdjacentHTML\s*\(\s*''', "html", 1),
    ("document.write",           r'''(?<![\w$])document\s*\.\s*write(?:ln)?\s*\(\s*''', "html", 0),
    ("createContextualFragment", r'''\.createContextualFragment\s*\(\s*''', "html", 0),
    ("srcdoc",                   r'''\.srcdoc\s*=(?!=)\s*''', "html", "rhs"),
    ("dangerouslySetInnerHTML",  r'''dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*''', "html", "expr"),
    ("v-html / innerHTML prop",  r'''(?<![\w$."'])innerHTML\s*:\s*''', "html", "expr"),
    ("jQuery .html()",           r'''\.html\(\s*(?=[^)\s])''', "html", 0),
    ("parseHTML",                r'''\.parseHTML\s*\(\s*''', "html", 0),
    ("eval",                     r'''(?<![\w$.])eval\s*\(\s*''', "code", 0),
    ("Function()",               r'''(?<![\w$.])(?:new\s+)?Function\s*\(\s*(?=[^)\s])''', "code", "allargs"),
    ("setTimeout/setInterval string", r'''(?<![\w$])set(?:Timeout|Interval)\s*\(\s*(?=["'`])''', "code", 0),
    ("location assignment",      r'''(?<![\w$.])(?:(?:window|document|self|top|parent)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)\s*''', "nav", "rhs"),
    ("location.assign/replace",  r'''(?<![\w$])location\s*\.\s*(?:assign|replace)\s*\(\s*''', "nav", 0),
    ("window.open",              r'''(?<![\w$])window\s*\.\s*open\s*\(\s*''', "nav", 0),
    ("setAttribute(dangerous)",  r'''\.setAttribute\s*\(\s*["'](?:src|href|action|formaction|srcdoc|on[a-z]+)["']\s*,\s*''', "nav", "expr"),
    ("Angular bypassSecurityTrust", r'''bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*''', "framework", 0),
]
_DOM_SINK_RES = [(label, re.compile(rx), kind, mode) for label, rx, kind, mode in _DOM_SINKS]

_DOM_SOURCE_RE = re.compile(
    r'''(?<![\w$])(?:(?:window|document|self|top)\s*\.\s*)?location\s*\.\s*(?:hash|search|href|pathname)\b'''
    r'''|(?<![\w$])document\s*\.\s*(?:URL|documentURI|baseURI|referrer|cookie)\b'''
    r'''|(?<![\w$])window\s*\.\s*name\b'''
    r'''|URLSearchParams\s*\(\s*(?:(?:window|document)\s*\.\s*)?location''')

_MSG_HANDLER_RE = re.compile(
    r'''addEventListener\s*\(\s*["']message["']\s*,\s*|(?<![\w$])onmessage\s*=(?!=)\s*''')
_POSTMESSAGE_RE = re.compile(r'''\.postMessage\s*\(\s*''')
_ORIGIN_CHECK_RE = re.compile(r'''\.origin\b|(?<![\w$.])origin\s*(?:[!=]==?|\.)''')

_LITERAL_TERM_RE = re.compile(
    r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`'''
    r'''|-?\d+(?:\.\d+)?|null|undefined|true|false|!0|!1''')

# `name = <expression on the same line>` — used to follow a source through one variable
_TAINT_ASSIGN_RE = re.compile(r'''(?<![\w$.])([A-Za-z_$][\w$]{0,60})\s*=(?![=>])([^;\n]{0,500})''')

MAX_DOM_FINDINGS_PER_FILE = 500
_DOM_ARG_LIMIT = 5000             # keeps hostile unterminated input linear
_DOM_NEARBY_LINES = 15
_DOM_TAINT_WINDOW = 3000          # chars: bounds the look-back on huge minified lines


def _is_constant_expr(expr: str) -> bool:
    """True if the expression is only string/number literals (concatenated)."""
    expr = _strip_parens(expr.strip())
    if not expr:
        return True
    return all(_LITERAL_TERM_RE.fullmatch(_strip_parens(t)) for t in _split_top_level(expr))


def _call_args(code: str, start: int, limit: int = _DOM_ARG_LIMIT) -> list[str]:
    """Arguments of a call whose '(' ends just before `start`."""
    args, pos = [], start
    for _ in range(16):
        arg = _scan_js_expr(code, pos, limit)
        args.append(arg)
        nxt = code.find(arg, pos) + len(arg) if arg else pos
        while nxt < len(code) and code[nxt] in " \t\r\n":
            nxt += 1
        if nxt >= len(code) or code[nxt] != ",":
            break
        pos = nxt + 1
    return args


def find_dom_issues(text: str) -> list[dict]:
    """
    Scan one file for DOM XSS sinks, postMessage issues and source→sink flow.
    Returns [{sink, kind, severity, flow, line, snippet}] (line is 1-based in `text`).
    """
    newlines = [i for i, ch in enumerate(text) if ch == "\n"]

    def line_of(pos):
        return bisect.bisect_left(newlines, pos) + 1

    def line_bounds(line):
        start = newlines[line - 2] + 1 if line >= 2 else 0
        end = newlines[line - 1] if line - 1 < len(newlines) else len(text)
        return start, end

    def snippet_at(pos):
        """The match's line, clipped to ~240 chars around the match (minified lines can be MBs)."""
        start, end = line_bounds(line_of(pos))
        a, b = max(start, pos - 80), min(end, pos + 160)
        return (("…" if a > start else "") + text[a:b].strip() + ("…" if b < end else ""))

    def tainted_vars_before(pos) -> set:
        """Variables assigned from a known source in the preceding lines (char-bounded)."""
        line = line_of(pos)
        first = max(1, line - _DOM_NEARBY_LINES)
        start = max(newlines[first - 2] + 1 if first >= 2 else 0, pos - _DOM_TAINT_WINDOW)
        names = set()
        for a in _TAINT_ASSIGN_RE.finditer(text, start, pos):
            if _DOM_SOURCE_RE.search(a.group(2)):
                names.add(a.group(1))
        return names

    findings = []

    def add(sink, kind, severity, flow, pos):
        if len(findings) < MAX_DOM_FINDINGS_PER_FILE:
            findings.append({"sink": sink, "kind": kind, "severity": severity, "flow": flow,
                             "line": line_of(pos), "snippet": snippet_at(pos)})

    # postMessage receivers first: inside a handler with no origin check,
    # event.data is attacker-controlled, so it counts as a source for sinks there.
    unchecked_spans = []
    for i, m in enumerate(_MSG_HANDLER_RE.finditer(text)):
        if i >= 200:
            break
        handler = _scan_js_expr(text, m.end(), 20000)
        is_inline = "{" in handler or "=>" in handler
        if not is_inline:
            add("message handler (defined elsewhere)", "postmessage", "low", None, m.start())
        elif not _ORIGIN_CHECK_RE.search(handler):
            start = text.find(handler, m.end())
            unchecked_spans.append((start, start + len(handler)))
            add("message handler without origin check", "postmessage", "high",
                "message data" if re.search(r"\.data\b", handler) else None, m.start())

    def in_unchecked_handler(pos):
        return any(a <= pos < b for a, b in unchecked_spans)

    for label, rx, kind, mode in _DOM_SINK_RES:
        for m in rx.finditer(text):
            if len(findings) >= MAX_DOM_FINDINGS_PER_FILE:
                break
            if mode in ("rhs", "expr"):
                arg = _scan_js_expr(text, m.end(), _DOM_ARG_LIMIT)
            else:
                args = _call_args(text, m.end())
                arg = ", ".join(args) if mode == "allargs" else (args[mode] if len(args) > mode else "")
            if _is_constant_expr(arg):
                continue                                  # fixed markup / URL: not controllable
            tainted = tainted_vars_before(m.start())
            via = next((v for v in sorted(tainted) if re.search(r"(?<![\w$.])" + re.escape(v) + r"(?![\w$])", arg)), None)
            if _DOM_SOURCE_RE.search(arg):
                flow, severity = "direct", "high"
            elif via:
                flow, severity = f"via variable '{via}'", "high"
            elif in_unchecked_handler(m.start()) and re.search(r"\.data\b", arg):
                flow, severity = "message data", "high"
            else:
                flow = None
                severity = "medium" if kind in ("code", "framework") else "low"
            add(label, kind, severity, flow, m.start())

    # postMessage senders targeting "*": data readable by whatever window is there
    for i, m in enumerate(_POSTMESSAGE_RE.finditer(text)):
        if i >= 500:
            break
        args = _call_args(text, m.end())
        if len(args) >= 2 and args[1].strip() in ('"*"', "'*'", "`*`"):
            add('postMessage(…, "*")', "postmessage", "medium", None, m.start())

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["line"]))
    return findings


def find_dom_issues_in_files(files: list[tuple[str, str, int]]) -> list[dict]:
    """
    Per-file DOM scan with real file:line locations (header_lines offset, like
    secrets). The same sink often appears in a bundle and in its recovered
    original source, so findings are grouped by (sink, normalised snippet).
    """
    grouped = {}
    for path, text, offset in files:
        for f in find_dom_issues(text):
            loc = {"file": path, "line": f["line"] + offset}
            key = (f["sink"], re.sub(r"\s+", "", f["snippet"]))
            if key not in grouped:
                grouped[key] = {**f, **loc, "locations": []}
            grouped[key]["locations"].append(loc)
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(grouped.values(), key=lambda f: (order[f["severity"]], f["file"], f["line"]))


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

    # Output shape varies across wappalyzer CLI versions/forks:
    #   {"urls": {...}, "technologies": [...]}  or a bare [...] list.
    # Categories may be dicts ({"name": ...}) or plain strings.
    if isinstance(data, dict):
        techs = data.get("technologies") or []
    elif isinstance(data, list):
        techs = data
    else:
        techs = []
    results = []
    for t in techs:
        if not isinstance(t, dict):
            continue
        cats = t.get("categories") or []
        results.append({
            "name": str(t.get("name") or "unknown"),
            "version": str(t.get("version") or ""),
            "categories": [
                str(c.get("name", "")) if isinstance(c, dict) else str(c)
                for c in (cats if isinstance(cats, list) else [])
            ],
        })

    print(f"  {green('[Wappalyzer]')} Identified {len(results)} technolog{'y' if len(results) == 1 else 'ies'}")
    return results


def run_retire(js_dirs: list[Path], timeout: int = 120) -> list[dict]:
    """
    Run retire.js (npm install -g retire) against every given directory —
    downloaded bundles, inline blocks AND source-map-recovered sources.
    Vendor code (node_modules/) is deliberately included here: recovered
    node_modules/<lib>/ files are exactly what retire.js fingerprints best.
    This is a local, signature-based CVE scanner — a useful complement to
    the live OSV.dev lookup in lookup_cves(), since it also catches
    hash-fingerprinted minified files that carry no version banner.

    Returns a list of {"file", "component", "version", "vulnerabilities": [...]}.
    """
    if shutil.which("retire") is None:
        print(f"  {yellow('[WARN]')} retire.js not found on PATH — skipping local CVE scan.")
        print(f"  {yellow('[WARN]')} Install: npm install -g retire")
        return []
    if not js_dirs:
        print(f"  {yellow('[WARN]')} No JS directory to scan with retire.js")
        return []

    results = []
    for d in js_dirs:
        results += _run_retire_dir(d, timeout)
    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    print(f"  {green('[retire.js]')} {len(results)} vulnerable component instance(s), "
          f"{total_vulns} finding(s) total")
    return results


def _run_retire_dir(js_dir: Path, timeout: int = 120) -> list[dict]:
    """retire.js against a single directory (it only accepts one --path)."""
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

    return results


def run_semgrep(target_dirs: list[Path], configs: list[str] = None, timeout: int = 300) -> list[dict]:
    """
    Run semgrep static analysis against downloaded bundles, inline blocks and
    source-map-recovered sources for dangerous client-side patterns (matches
    the manual step: `semgrep --config "p/xss" ./`). Recovered first-party
    sources are the most valuable target: readable, unminified code where
    source→sink flows are actually visible. Vendor code is excluded.

    Returns a list of {"rule_id", "file", "line", "message", "severity"}.
    """
    if shutil.which("semgrep") is None:
        print(f"  {yellow('[WARN]')} semgrep not found on PATH — skipping static analysis.")
        print(f"  {yellow('[WARN]')} Install: pip install semgrep  (or: pip install --break-system-packages semgrep)")
        return []
    if not target_dirs:
        print(f"  {yellow('[WARN]')} No JS directory to scan with semgrep")
        return []

    configs = configs or ["p/xss", "p/javascript"]
    cmd = ["semgrep", "--json", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    for d in VENDOR_DIR_NAMES:
        cmd += ["--exclude", d]
    cmd += [str(d) for d in target_dirs]

    where = ", ".join(str(d) for d in target_dirs)
    print(f"  {cyan('[semgrep]')} Running static analysis ({', '.join(configs)}) on {where}...")
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


def run_linkfinder(target_dirs: list[Path], linkfinder_path: str = "", timeout: int = 120) -> list[str]:
    """
    Run LinkFinder (https://github.com/GerbenJavado/LinkFinder) against every
    script/source file in target_dirs (bundles, inline blocks, recovered
    .js/.ts/.vue/... sources; vendor code skipped) to extract endpoint-like
    strings — a complement to our own extract_endpoints() regex pass, using
    LinkFinder's own patterns.

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
    js_files = [
        f for d in target_dirs for f in sorted(d.rglob("*"))
        if f.is_file() and f.suffix.lower() in SOURCE_EXTENSIONS and not is_vendor_path(f, d)
    ]
    if not js_files:
        print(f"  {yellow('[WARN]')} No script files under {', '.join(map(str, target_dirs))} for LinkFinder to scan")
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

def save_js(content: str, path: Path, url: str = "") -> int:
    """
    Write beautified JS to disk with an optional source comment header.
    Returns how many lines the header adds, so line numbers computed on
    `content` can be mapped to the file on disk.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    header = f"/* Source: {url.replace('*/', '*_/')} */\n\n" if url else ""
    path.write_text(header + content, encoding="utf-8")
    print(f"  {green('[OK]')} Saved -> {path.name}")
    return header.count("\n")


# ══════════════════════════════════════════════════════════════════════════════
# HTML Report generator
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(data: dict, out_dir: Path) -> Path:
    """Build a self-contained HTML analysis report."""
    # Everything in `data` comes from the target (JS contents, URLs, tool
    # output) and must be treated as hostile: escape every interpolated value
    # and only allow http(s) links. The CSP below is defence in depth.
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def e(value) -> str:
        return html_escape(str(value), quote=True)

    def safe_href(url) -> str:
        url = str(url).strip()
        return e(url) if urlparse(url).scheme.lower() in ("http", "https") else "#"

    def badge(text, color):
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{e(text)}</span>'

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
          <td style="word-break:break-all"><a href="{e(f['saved_path'])}" target="_blank" rel="noopener noreferrer">{e(f['filename'])}</a></td>
          <td><a href="{safe_href(f['url'])}" target="_blank" rel="noopener noreferrer" style="font-size:11px">{e(f['url'][:80])}{'...' if len(f['url'])>80 else ''}</a></td>
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
        ep_rows += f"<tr><td style='padding:5px;font-family:monospace;word-break:break-all'>{e(ep)}{flag}</td></tr>\n"
    ep_html = f"<table style='width:100%;border-collapse:collapse'>{ep_rows}</table>" if ep_rows else "<i>No endpoints extracted (use --endpoints)</i>"

    # ── Params ───────────────────────────────────────────────────────────────
    param_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;display:inline-block">{e(p)}</code>'
        for p in data.get("params", [])
    ) or "<i>No params extracted (use --params)</i>"

    # Wordlist file path
    wordlist_note = ""
    if data.get("params"):
        wordlist_note = f'<p style="margin-top:8px">📄 Wordlist saved to: <code>{e(data.get("wordlist_path",""))}</code></p>'

    # ── Secrets ──────────────────────────────────────────────────────────────
    sec_rows = ""
    for s in data.get("secrets", []):
        locs = s.get("locations") or [{"file": s.get("file", ""), "line": s["line"]}]
        loc_html = "<br>".join(f"{e(l['file'])}:{e(l['line'])}" for l in locs[:5])
        if len(locs) > 5:
            loc_html += f"<br><i>+{len(locs) - 5} more (see secrets.json)</i>"
        sec_rows += (
            f"<tr>"
            f"<td style='padding:5px'>{badge(s['type'], '#dc2626')}</td>"
            f"<td style='padding:5px;font-family:monospace'>{e(mask_secret(s['value']))}</td>"
            f"<td style='padding:5px;font-family:monospace;font-size:12px;word-break:break-all'>{loc_html}</td>"
            f"</tr>\n"
        )
    sec_html = (
        f"<table style='width:100%;border-collapse:collapse'>{sec_rows}</table>"
        if sec_rows else "<i>No secrets found (use --secrets)</i>"
    )

    # ── DOM sinks ────────────────────────────────────────────────────────────
    dom_all = data.get("dom_findings", [])
    dom_shown = [d for d in dom_all if d["severity"] != "low"][:300]
    sev_colour = {"high": "#dc2626", "medium": "#d97706", "low": "#64748b"}
    dom_rows = ""
    for d in dom_shown:
        more = f" <i>(+{len(d['locations']) - 1} more)</i>" if len(d.get("locations", [])) > 1 else ""
        flow = f"<br><small>{e(d['flow'])} source</small>" if d.get("flow") else ""
        dom_rows += (
            f"<tr><td style='padding:5px'>{badge(d['severity'], sev_colour[d['severity']])}</td>"
            f"<td style='padding:5px;font-size:12px'>{e(d['sink'])}{flow}</td>"
            f"<td style='padding:5px;font-family:monospace;font-size:12px;word-break:break-all'>"
            f"{e(d['file'])}:{e(d['line'])}{more}</td>"
            f"<td style='padding:5px;font-family:monospace;font-size:12px;word-break:break-all'>{e(d['snippet'])}</td></tr>\n"
        )
    n_low = sum(1 for d in dom_all if d["severity"] == "low")
    if dom_rows:
        dom_html = (f"<table style='width:100%;border-collapse:collapse'>"
                    f"<tr style='background:#f1f5f9;font-weight:bold'><th style='padding:8px;text-align:left'>Severity</th>"
                    f"<th style='padding:8px;text-align:left'>Sink</th><th style='padding:8px;text-align:left'>Location</th>"
                    f"<th style='padding:8px;text-align:left'>Code</th></tr>{dom_rows}</table>")
    else:
        dom_html = "<i>No high/medium DOM findings (or --dom was not used)</i>"
    if n_low:
        dom_html += f"<p><i>+ {n_low} low-severity sink(s) with no known source nearby — see dom_sinks.json</i></p>"

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
                f'<a href="{safe_href(c["url"])}" target="_blank" rel="noopener noreferrer">{badge(c["cve"] or c["id"], "#dc2626")}</a>'
                for c in hits
            )
            status = cve_badges
        else:
            status = badge("no known CVEs", "#16a34a")
        lib_rows += f"""<tr>
          <td style="padding:5px;font-family:monospace">{e(l['name'])}</td>
          <td style="padding:5px;font-family:monospace">{e(l['version'])}</td>
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
          <td style="padding:5px;font-family:monospace">{e(c['library'])}@{e(c['version'])}</td>
          <td style="padding:5px">{e(c['severity']) if c['severity'] else '<i>n/a</i>'}</td>
          <td style="padding:5px;font-size:12px">{e(c['summary'])}</td>
          <td style="padding:5px"><a href="{safe_href(c['url'])}" target="_blank" rel="noopener noreferrer">osv.dev</a></td>
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
        f'{e(t["name"])}{" v" + e(t["version"]) if t["version"] else ""}</code>'
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
              <td style="padding:5px;font-family:monospace">{e(r['component'])}@{e(r['version'])}</td>
              <td style="padding:5px">{e(v.get('severity', '')) if v.get('severity') else '<i>n/a</i>'}</td>
              <td style="padding:5px;font-size:12px;word-break:break-all">{e(r['file'])}</td>
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
          <td style="padding:5px;font-family:monospace;font-size:12px">{e(s['rule_id'])}</td>
          <td style="padding:5px;font-size:12px">{e(s['file'])}:{e(s['line'])}</td>
          <td style="padding:5px;font-size:12px">{e(s['message'])}</td>
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
        f'display:inline-block;word-break:break-all">{e(lf)}</code>'
        for lf in data.get("linkfinder_endpoints", [])
    ) or "<i>No LinkFinder results (or --linkfinder was not used)</i>"

    # ── Routes (Next.js build manifest) ───────────────────────────────────────
    route_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;'
        f'display:inline-block;word-break:break-all">{e(r)}</code>'
        for r in data.get("routes", [])
    ) or "<i>No client-side routes recovered</i>"
    ch = data.get("chunks") or {}
    if ch.get("candidates"):
        route_chips = (f"<p>Lazy chunks: <b>{e(ch.get('found', 0))}</b> found from {e(ch['candidates'])} "
                       f"candidate URLs ({e(ch.get('webpack_runtimes', 0))} webpack runtime(s))</p>"
                       + route_chips)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>JS Extractor Report — {e(data['target_url'])}</title>
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
    Target: <a href="{safe_href(data['target_url'])}" target="_blank" rel="noopener noreferrer">{e(data['target_url'])}</a>
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
  {section("🧭 Routes & Lazy Chunks", route_chips, "#0891b2")}
  {section("🔑 Parameters (Fuzzing Wordlist)", param_chips + wordlist_note, "#059669")}
  {section("⚠️ Potential Secrets / Credentials", sec_html, "#dc2626")}
  {section("🎯 DOM XSS Sinks & postMessage", dom_html, "#dc2626")}
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

FAIL_ON_CHOICES = ("secrets", "cves", "hidden-endpoints", "retire", "semgrep", "dom")

try:
    from js_extractor import __version__
except ImportError:                       # run directly as a script
    __version__ = "unknown"


def looks_like_html(text: str) -> bool:
    """A 'script' that is really an HTML page (soft 404, login redirect, WAF page)."""
    head = text.lstrip("﻿ \t\r\n")[:64].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def write_results(path: Path, results: dict, stream=None):
    """Write results.json and, with --json, the same document to `stream`."""
    doc = json.dumps(results, indent=2, ensure_ascii=False, default=str)
    path.write_text(doc + "\n", encoding="utf-8")
    if stream is not None:
        stream.write(doc + "\n")
        stream.flush()


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
    auth.add_argument("--auth-scope", choices=("host", "domain"), default="host",
        help="Where --cookie/--jwt/--header are sent: 'host' = exact target host only (default); "
             "'domain' = target's registrable domain and all its subdomains")

    # Network
    net = parser.add_argument_group("Network")
    net.add_argument("--proxy", default=None, metavar="URL",
        help="Send all target traffic through this proxy, e.g. http://127.0.0.1:8080 (Burp) or "
             "socks5://127.0.0.1:9050. Applies to requests, --dynamic, katana and httpx; not to "
             "gau/OSV/semgrep, which only talk to public services")
    net.add_argument("--insecure", "-k", action="store_true",
        help="Skip TLS certificate verification (self-signed targets, intercepting proxies)")
    net.add_argument("--ca-cert", default=None, metavar="PATH",
        help="Verify TLS against this CA bundle (e.g. Burp's exported CA in PEM). "
             "Not usable by --dynamic: Chromium needs --insecure behind an intercepting proxy")

    # Performance
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--threads", "-t", type=int, default=5, metavar="N",
        help="Parallel script downloads (default: 5)")
    perf.add_argument("--rate-limit", type=float, default=10, metavar="RPS",
        help="Max requests per second across all threads, 0 = unlimited (default: 10)")
    perf.add_argument("--max-files", type=int, default=0, metavar="N",
        help="Download at most N external scripts, 0 = unlimited (default). Useful with --gau")
    perf.add_argument("--max-size", type=float, default=30, metavar="MB",
        help="Skip any response larger than this, 0 = unlimited (default: 30 MB)")

    # Scope
    scp = parser.add_argument_group("Scope")
    scp.add_argument("--scope", choices=Scope.MODES, default="any",
        help="Hosts the tool may send ANY request to: 'any' (default), 'domain' = target's "
             "registrable domain + subdomains, 'host' = exact target host only. Also narrows katana "
             "(-fs fqdn), gau (no --subs) and httpx (same-host redirects only), and makes --dynamic "
             "block out-of-scope browser requests")
    scp.add_argument("--include-host", action="append", metavar="PATTERN",
        help="Extra allowed host for --scope host/domain, glob allowed (e.g. 'cdn.example-static.com', "
             "'*.example.net'). Repeatable")
    scp.add_argument("--exclude-host", action="append", metavar="PATTERN",
        help="Never send requests to this host, glob allowed (e.g. '*.google-analytics.com'). "
             "Applies in every --scope mode and wins over --include-host. Repeatable")

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
    ext.add_argument("--no-chunks", action="store_true",
        help="Skip lazy-chunk discovery (webpack runtime chunk maps, Next.js _buildManifest, "
             "Vite manifest / preload lists)")
    ext.add_argument("--no-imports", action="store_true",
        help="Skip following import/require chains")

    # Analysis
    ana = parser.add_argument_group("Analysis")
    ana.add_argument("--endpoints", action="store_true",
        help="Extract API endpoints (includes hidden/internal detection)")
    ana.add_argument("--params", action="store_true",
        help="Extract parameters for fuzzing; saves params.txt wordlist")
    ana.add_argument("--dom", action="store_true",
        help="Map DOM XSS sinks (innerHTML, eval, location, ...), sources (location.hash, ...) and "
             "postMessage handlers without origin checks, ranked by source→sink flow; saves dom_sinks.json")
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
    ana.add_argument("--tool-timeout", type=int, default=None, metavar="SECONDS",
        help="Timeout for each external tool run (katana, gau, httpx, wappalyzer, retire, semgrep, "
             "LinkFinder per file). Default: per-tool (60-300s). On timeout, partial katana/gau/httpx "
             "output is kept.")
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
    out.add_argument("--json", action="store_true",
        help="Print machine-readable results (same as results.json, which is always written) to "
             "stdout; all progress output goes to stderr")
    out.add_argument("--fail-on", default="", metavar="LIST",
        help="Exit with code 3 if any of these were found (comma-separated): "
             f"{', '.join(FAIL_ON_CHOICES)}. For CI / scripting")

    args = parser.parse_args()

    fail_on = [f.strip() for f in args.fail_on.split(",") if f.strip()]
    bad = [f for f in fail_on if f not in FAIL_ON_CHOICES]
    if bad:
        parser.error(f"--fail-on: unknown value(s) {', '.join(bad)}; choose from {', '.join(FAIL_ON_CHOICES)}")
    if not 1 <= args.threads <= 64:
        parser.error("--threads must be between 1 and 64")
    if args.rate_limit < 0 or args.max_files < 0 or args.max_size < 0:
        parser.error("--rate-limit, --max-files and --max-size must not be negative")

    # --json: stdout carries only the JSON document; all progress → stderr
    if args.json:
        json_stream = sys.stdout
        with contextlib.redirect_stdout(sys.stderr):
            code = _run(args, parser, fail_on, json_stream)
    else:
        code = _run(args, parser, fail_on, None)
    if code:
        sys.exit(code)


def _run(args, parser, fail_on: list, json_stream) -> int:
    """Everything after argument parsing. Returns the process exit code."""
    started = time.monotonic()

    # --all-analysis shortcut
    if args.all_analysis:
        args.endpoints = args.params = args.secrets = args.cve = args.dom = True
        args.wappalyzer = args.retire = args.semgrep = args.linkfinder = True

    # --fail-on X implies the analysis that produces X (otherwise it could
    # never trigger and a CI gate would silently always pass)
    for f, flag in (("secrets", "secrets"), ("cves", "cve"), ("hidden-endpoints", "endpoints"), ("dom", "dom"),
                    ("retire", "retire"), ("semgrep", "semgrep")):
        if f in fail_on:
            setattr(args, flag, True)

    if args.tool_timeout is not None and args.tool_timeout <= 0:
        parser.error("--tool-timeout must be a positive number of seconds")
    # Passed as **kwargs so each tool keeps its own default unless overridden
    tool_timeout = {"timeout": args.tool_timeout} if args.tool_timeout else {}

    # ── Network / scope validation ───────────────────────────────────────────
    if not urlparse(args.url).scheme in ("http", "https") or not urlparse(args.url).hostname:
        parser.error(f"target must be an absolute http(s) URL, got: {args.url!r}")
    if args.proxy:
        p = urlparse(args.proxy)
        if p.scheme not in ("http", "https", "socks5", "socks5h", "socks4") or not p.hostname or not p.port:
            parser.error("--proxy must look like http://HOST:PORT or socks5://HOST:PORT")
        if p.scheme.startswith("socks"):
            try:
                import socks  # noqa: F401  (PySocks, needed by requests for SOCKS)
            except ImportError:
                parser.error('SOCKS proxies need PySocks: pip install "requests[socks]"')
    if args.insecure and args.ca_cert:
        parser.error("use either --insecure or --ca-cert, not both")
    if args.ca_cert and not Path(args.ca_cert).is_file():
        parser.error(f"--ca-cert file not found: {args.ca_cert}")
    if args.include_host and args.scope == "any":
        print(f"{yellow('[WARN]')} --include-host has no effect with --scope any")

    scope = Scope(args.url, args.scope, args.include_host, args.exclude_host)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    limiter = RateLimiter(args.rate_limit)
    max_bytes = int(args.max_size * 1048576) if args.max_size else 0
    session = make_session(args, scope, limiter, max_bytes)
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Step 1: Fetch the page ────────────────────────────────────────────────
    print(f"\n{bold('[*]')} Target: {cyan(args.url)}")
    print(f"    Scope: {scope.describe()}   Auth scope: "
          f"{'*.' + base_domain(urlparse(args.url).hostname) if args.auth_scope == 'domain' else urlparse(args.url).hostname}")
    if args.proxy:
        tls = "insecure" if args.insecure else (f"CA {args.ca_cert}" if args.ca_cert else "verified")
        print(f"    Proxy: {args.proxy}   TLS: {tls}")
        if not (args.insecure or args.ca_cert):
            print(f"    {yellow('[WARN]')} Intercepting proxies (Burp/ZAP) re-sign TLS: add --ca-cert "
                  f"<proxy CA .pem> or --insecure, else HTTPS fetches will fail")
        if args.dynamic and not args.insecure:
            print(f"    {yellow('[WARN]')} --dynamic behind an intercepting proxy needs --insecure "
                  f"(Chromium can't load a CA file)")
        if args.wappalyzer:
            print(f"    {yellow('[WARN]')} wappalyzer runs its own browser and does NOT use --proxy")
    if args.wappalyzer and scope.restricted:
        print(f"    {yellow('[WARN]')} wappalyzer loads the page in its own browser and does NOT honour --scope")
    print()
    resp = fetch(args.url, session)
    if not resp:
        write_results(output_dir / "results.json", {
            "tool": "js-extractor", "version": __version__, "target": args.url,
            "error": f"could not fetch target ({session.fetch_error or 'error'})",
        }, json_stream)
        return 1
    base_html = resp.text

    # Tech-stack fingerprinting (independent of JS extraction, so run it first)
    wappalyzer_techs = []
    if args.wappalyzer:
        print(f"{bold('[*]')} Tech-stack fingerprinting...")
        wappalyzer_techs = run_wappalyzer(args.url, **tool_timeout)
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
            headers=build_auth_headers(args),
            cookies=build_cookies(args),
            scope_mode=args.scope,
            auth_mode=args.auth_scope,
            proxy=args.proxy,
            **tool_timeout,
        )
        all_ext_urls = list(dict.fromkeys(all_ext_urls + katana_js))

    # ── gau: historical URL collection, optionally filtered through httpx ─────
    if args.gau:
        domain = urlparse(args.url).hostname
        providers = [p.strip() for p in args.gau_providers.split(",") if p.strip()] or None
        gau_urls = run_gau(domain, providers=providers, subs=(args.scope != "host"), **tool_timeout)
        if scope.restricted and gau_urls:
            kept = [u for u in gau_urls if scope.allows(u)]
            if len(kept) != len(gau_urls):
                print(f"  {yellow('[Scope]')} Dropped {len(gau_urls) - len(kept)} out-of-scope gau URL(s)")
            gau_urls = kept

        if gau_urls:
            if args.httpx_probe:
                alive = run_httpx_probe(
                    gau_urls,
                    headers=build_auth_headers(args),
                    cookies=build_cookies(args),
                    target_url=args.url,
                    auth_mode=args.auth_scope,
                    proxy=args.proxy,
                    same_host_redirects=scope.restricted,
                    **tool_timeout,
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

    # Inline blocks can reference scripts too — service worker registration
    # and inline <script type="module"> imports usually live there. Resolve
    # against the final page URL (after redirects).
    if not args.no_inline and all_inline:
        page_url = resp.url or args.url
        from_inline = []
        for code in all_inline:
            if not args.no_workers:
                from_inline += find_workers(code, page_url)
            if not args.no_imports:
                from_inline += find_js_imports(code, page_url)
        new = [u for u in dict.fromkeys(from_inline) if u not in all_ext_urls]
        if new:
            print(f"  {green('[Inline]')} {len(new)} worker/import script(s) referenced from inline blocks")
            all_ext_urls = all_ext_urls + new

    # Out-of-scope scripts are listed (not fetched) so the tester can decide
    # whether to widen the scope with --include-host.
    out_of_scope = [u for u in all_ext_urls if not scope.allows(u)]
    all_ext_urls = [u for u in all_ext_urls if scope.allows(u)]

    print(f"{bold('[*]')} Discovered: {len(all_ext_urls)} external script(s), {len(all_inline)} inline block(s)"
          + (f", {len(out_of_scope)} out of scope (not fetched)" if out_of_scope else "") + "\n")

    # Accumulate all JS text for analysis and optional merge
    all_js_text = ""
    all_contents_merge = []
    file_records = []         # for report
    workers_to_fetch = set()
    imports_to_fetch = set()
    recovered_paths = []      # source-map-recovered files written this run
    # (path shown to the user, text, lines prepended on disk) — lets secret
    # findings point at the real file and line instead of a concatenated blob
    analysis_files = []

    # ── Step 3: Download & beautify external scripts ──────────────────────────
    skipped = {"failed": [], "too_large": [], "not_javascript": [], "max_files": [], "guess_missed": []}
    page_url = resp.url or args.url

    # Lazy-chunk discovery state. Chunk URLs built from bundler metadata are
    # "guesses": fetched quietly, and a miss (404, or the index.html an SPA
    # server returns for any path) is recorded as guess_missed, not an error.
    chunk_templates, chunk_ids, routes, vite_sources = [], set(), set(), []
    guessed = set()
    chunk_stats = {"webpack_runtimes": 0, "candidates": 0, "found": 0}

    def add_guesses(urls):
        new = [u for u in urls if u and u not in guessed and u not in all_ext_urls]
        guessed.update(new)
        return new

    if not args.no_chunks and not args.no_external:
        # CRA inlines the webpack runtime into index.html by default
        if not args.no_inline:
            for code in all_inline:
                chunk_templates += find_chunk_templates(code, page_url)
                chunk_ids |= find_chunk_ids(code)
        # Next.js: _buildManifest.js from the buildId, even if not referenced
        all_ext_urls += add_guesses(next_build_manifest_urls(base_html, all_ext_urls, page_url))
        # Vite: build manifest, if it was deployed publicly
        for mpath in ("/.vite/manifest.json", "/manifest.json"):
            mresp = fetch(urljoin(page_url, mpath), session, quiet=True)
            if mresp is not None and not looks_like_html(mresp.text):
                files, sources = parse_vite_manifest(mresp.text, urljoin(page_url, "/"))
                if files:
                    print(f"  {green('[Chunks]')} Vite manifest {mpath}: {len(files)} chunk(s), "
                          f"{len(sources)} source path(s)")
                    vite_sources += sources
                    all_ext_urls += [u for u in files if u not in all_ext_urls]

    if not args.no_external:
        ext_dir = output_dir / "external"
        local = threading.local()
        target_cookies = session.cookies.copy()      # cookies the target set on page load

        def thread_session():
            if not hasattr(local, "session"):
                local.session = make_session(args, scope, limiter, max_bytes, target_cookies)
            return local.session

        def download(idx: int, src_url: str, is_guess: bool) -> dict:
            """Network + CPU part, run in worker threads. No shared state touched."""
            s = thread_session()
            if not is_guess:
                print(f"  {cyan('[DL]')} {src_url}")
            js_resp = fetch(src_url, s, quiet=is_guess)
            if not js_resp:
                return {"idx": idx, "url": src_url, "guess": is_guess, "error": s.fetch_error or "error"}
            raw = js_resp.text
            if looks_like_html(raw):
                if not is_guess:
                    print(f"  {yellow('[SKIP]')} {src_url} returned an HTML page, not JS (soft 404 / login / WAF?)")
                return {"idx": idx, "url": src_url, "guess": is_guess, "error": "not_javascript"}
            if is_guess:
                print(f"  {green('[Chunk]')} {src_url}")
            recovered = []
            if not args.no_sourcemaps:
                try_recover_sourcemap(raw, src_url, s, output_dir,
                                      headers=js_resp.headers, written=recovered)
            chunks = {}
            if not args.no_chunks:
                next_chunks, next_routes = parse_next_build_manifest(raw, src_url)
                chunks = {
                    "templates": find_chunk_templates(raw, src_url),
                    "ids": find_chunk_ids(raw),
                    "urls": find_asset_paths(raw, src_url, page_url) + next_chunks,
                    "routes": next_routes,
                }
            return {
                "idx": idx, "url": src_url, "guess": is_guess, "error": None,
                "beautified": beautify(raw),
                "recovered": recovered,
                "imports": [] if args.no_imports else find_js_imports(raw, src_url),
                "workers": [] if args.no_workers else find_workers(raw, src_url),
                "chunks": chunks,
            }

        def chunk_candidates() -> list:
            """Every chunk URL the known runtimes can build from all ids seen so far."""
            urls = []
            for t in chunk_templates:
                for cid in sorted(t.known_ids | chunk_ids):
                    urls.append(t.url_for(cid, page_url))
            return add_guesses(u for u in urls if u not in seen)

        # Breadth-first in waves: each wave downloads in parallel, then results
        # are handled in submission order, so file numbering and analysis
        # output are identical from run to run regardless of thread timing.
        seen, pending, n_queued = set(), list(all_ext_urls), 0
        pending += chunk_candidates()                  # from an inline runtime
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            while pending:
                wave = []
                for u in pending:
                    if u in seen:
                        continue
                    seen.add(u)
                    if not scope.allows(u):            # imports/workers found along the way
                        out_of_scope.append(u)
                    elif args.max_files and n_queued >= args.max_files:
                        skipped["max_files"].append(u)
                    else:
                        n_queued += 1
                        wave.append((n_queued, u, u in guessed))
                pending = []

                for res in pool.map(lambda w: download(*w), wave):
                    if res["error"] == "out_of_scope":   # redirected out of scope
                        out_of_scope.append(res["url"])
                        continue
                    if res["error"]:
                        if res["guess"] and res["error"] != "too_large":
                            key = "guess_missed"
                        else:
                            key = res["error"] if res["error"] in skipped else "failed"
                        skipped[key].append(res["url"])
                        continue
                    if res["guess"]:
                        chunk_stats["found"] += 1
                    ch = res["chunks"]
                    if ch:
                        chunk_templates.extend(ch["templates"])
                        chunk_ids.update(ch["ids"])
                        routes.update(ch["routes"])
                        pending += add_guesses(u for u in ch["urls"] if u not in seen)
                    src_url, beautified = res["url"], res["beautified"]
                    all_js_text += beautified + "\n"
                    fname = safe_filename(src_url, prefix=f"ext_{res['idx']:03d}")
                    fpath = ext_dir / fname
                    header_lines = save_js(beautified, fpath, url=src_url)
                    analysis_files.append((str(fpath.relative_to(output_dir)), beautified, header_lines))
                    file_records.append({"kind": "external", "filename": fname,
                                         "url": src_url, "saved_path": str(fpath.relative_to(output_dir)),
                                         "size_kb": fpath.stat().st_size / 1024})
                    recovered_paths.extend(res["recovered"])
                    imports_to_fetch.update(res["imports"])
                    workers_to_fetch.update(res["workers"])
                    pending += [u for u in res["imports"] + res["workers"] if u not in seen]
                    all_contents_merge.append(
                        f"\n\n{'='*70}\n// FILE: {fname}\n// SOURCE: {src_url}\n{'='*70}\n\n"
                        + beautified
                    )

                # New runtimes/ids from this wave → more chunk URLs for the next
                if not args.no_chunks:
                    pending += chunk_candidates()

        chunk_stats["webpack_runtimes"] = len(chunk_templates)
        chunk_stats["candidates"] = len(guessed)
        if guessed:
            print(f"\n  {green('[Chunks]')} {chunk_stats['found']} lazy chunk(s) found from "
                  f"{len(guessed)} candidate URL(s) ({len(chunk_templates)} webpack runtime(s), "
                  f"{len(routes)} route(s))")
        if routes:
            routes_path = output_dir / "routes.txt"
            routes_path.write_text("\n".join(sorted(routes)) + "\n", encoding="utf-8")
            print(f"  Routes -> {routes_path}")

        if skipped["max_files"]:
            print(f"\n  {yellow('[Limit]')} --max-files {args.max_files} reached: "
                  f"{len(skipped['max_files'])} script(s) not downloaded")

    if out_of_scope:
        oos_path = output_dir / "out_of_scope.txt"
        oos_path.write_text("\n".join(dict.fromkeys(out_of_scope)) + "\n", encoding="utf-8")
        print(f"\n  {yellow('[Scope]')} {len(set(out_of_scope))} out-of-scope script URL(s) not fetched "
              f"({scope.describe()}) -> {oos_path}")

    # ── Step 4: Inline script blocks ──────────────────────────────────────────
    if not args.no_inline and all_inline:
        inline_dir = output_dir / "inline"
        print(f"\n{bold('[*]')} Saving {len(all_inline)} inline block(s)...")
        for i, code in enumerate(all_inline, 1):
            beautified = beautify(code)
            all_js_text += beautified + "\n"
            fname = f"inline_{i:03d}.js"
            fpath = inline_dir / fname
            header_lines = save_js(beautified, fpath)
            analysis_files.append((str(fpath.relative_to(output_dir)), beautified, header_lines))
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

    # Fold source-map-recovered originals into the analysis. First-party code
    # feeds every regex pass; vendor (node_modules) code only feeds framework
    # and library-version detection, where it helps instead of adding noise.
    sm_root = (output_dir / "sourcemap_recovered").resolve()
    sm_app_files, sm_vendor_text, n_sm_vendor = read_recovered_sources(recovered_paths, sm_root)
    n_sm_app = len(sm_app_files)
    if n_sm_app or n_sm_vendor:
        print(f"\n{bold('[SourceMap]')} Including {n_sm_app} first-party + {n_sm_vendor} vendor "
              f"recovered source file(s) in analysis")
    out_root = output_dir.resolve()
    for p, text in sm_app_files:
        all_js_text += text + "\n"
        analysis_files.append((str(p.relative_to(out_root)), text, 0))
    fingerprint_text = all_js_text + sm_vendor_text
    report_data["sourcemap_files"] = {"first_party": n_sm_app, "vendor": n_sm_vendor}
    report_data["routes"] = sorted(routes)
    report_data["chunks"] = chunk_stats

    # Framework detection (always runs if we have JS)
    frameworks = detect_frameworks(fingerprint_text) if fingerprint_text else []
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
    if args.secrets and analysis_files:
        print(f"\n{bold('[Secrets]')} Scanning for leaked credentials...")
        secrets = find_secrets_in_files(analysis_files)
        report_data["secrets"] = secrets

        # Full, unmasked values + every location: needed to validate findings.
        # Terminal and HTML report only ever show masked values.
        secrets_path = output_dir / "secrets.json"
        secrets_path.write_text(json.dumps(secrets, indent=2, ensure_ascii=False), encoding="utf-8")

        if secrets:
            print(f"  {red(f'[!] {len(secrets)} potential secret(s) found:')}")
            for s in secrets:
                more = f" (+{len(s['locations']) - 1} more)" if len(s["locations"]) > 1 else ""
                print(f"      {red('[' + s['type'] + ']')} {mask_secret(s['value'])}  "
                      f"{s['file']}:{s['line']}{more}")
        else:
            print(f"  {green('No secrets detected.')}")
        print(f"  Saved -> {secrets_path}  (unmasked — handle with care)")

    # DOM XSS sinks / sources / postMessage
    report_data["dom_findings"] = []
    if args.dom and analysis_files:
        print(f"\n{bold('[DOM]')} Mapping DOM XSS sinks, sources and postMessage handlers...")
        dom = find_dom_issues_in_files(analysis_files)
        report_data["dom_findings"] = dom
        dom_path = output_dir / "dom_sinks.json"
        dom_path.write_text(json.dumps(dom, indent=2, ensure_ascii=False), encoding="utf-8")
        counts = {s: sum(1 for d in dom if d["severity"] == s) for s in ("high", "medium", "low")}
        print(f"  {red(str(counts['high']) + ' high')}, {yellow(str(counts['medium']) + ' medium')}, "
              f"{counts['low']} low")
        for d in [d for d in dom if d["severity"] != "low"][:15]:
            flow = f" [{d['flow']} source]" if d["flow"] else ""
            colour = red if d["severity"] == "high" else yellow
            print(f"    {colour('[' + d['severity'] + ']')} {d['sink']}{flow}  {d['file']}:{d['line']}")
            print(f"        {d['snippet'][:140]}")
        print(f"  Saved -> {dom_path}")

    # Library versions + CVE matching
    report_data["libraries"] = []
    report_data["cves"] = []
    if args.cve and fingerprint_text:
        print(f"\n{bold('[CVE]')} Fingerprinting library versions...")
        libs = detect_library_versions(fingerprint_text)
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
        retire_findings = run_retire(analysis_dirs(output_dir), **tool_timeout)
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
        semgrep_findings = run_semgrep(analysis_dirs(output_dir), configs=args.semgrep_config, **tool_timeout)
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
        lf_endpoints = run_linkfinder(analysis_dirs(output_dir), linkfinder_path=args.linkfinder_path,
                                      **tool_timeout)
        report_data["linkfinder_endpoints"] = lf_endpoints
        if lf_endpoints:
            lf_path = output_dir / "linkfinder_endpoints.txt"
            lf_path.write_text("\n".join(lf_endpoints), encoding="utf-8")
            print(f"  Saved -> {lf_path}")

    # HTML report
    if args.report:
        rpath = generate_report(report_data, output_dir)
        print(f"\n{green('[Report]')} HTML report -> {rpath}")

    # ── Machine-readable results ──────────────────────────────────────────────
    hits = {
        "secrets": len(report_data.get("secrets", [])),
        "cves": len(report_data.get("cves", [])),
        "hidden-endpoints": len(report_data.get("hidden_endpoints", [])),
        "dom": sum(1 for d in report_data.get("dom_findings", []) if d["severity"] == "high"),
        "retire": sum(len(r["vulnerabilities"]) for r in report_data.get("retire_findings", [])),
        "semgrep": len(report_data.get("semgrep_findings", [])),
    }
    results = {
        "tool": "js-extractor",
        "version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "target": args.url,
        "final_url": resp.url,
        "scope": {"mode": args.scope, "allowed": scope.describe(), "auth_scope": args.auth_scope},
        "stats": {
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "external_downloaded": sum(1 for f in file_records if f["kind"] == "external"),
            "inline_blocks": sum(1 for f in file_records if f["kind"] == "inline"),
            "sourcemap_files": report_data.get("sourcemap_files", {}),
            "chunks": chunk_stats,
            "out_of_scope": len(set(out_of_scope)),
            **{f"skipped_{k}": len(v) for k, v in skipped.items()},
            "findings": hits,
        },
        "files": [{k: f[k] for k in ("kind", "url", "saved_path")} | {"size_kb": round(f["size_kb"], 1)}
                  for f in file_records],
        "frameworks": report_data.get("frameworks", []),
        "technologies": report_data.get("technologies", []),
        "endpoints": report_data.get("endpoints", []),
        "hidden_endpoints": report_data.get("hidden_endpoints", []),
        "params": report_data.get("params", []),
        "secrets": report_data.get("secrets", []),          # unmasked, like secrets.json
        "dom_findings": report_data.get("dom_findings", []),
        "libraries": report_data.get("libraries", []),
        "cves": report_data.get("cves", []),
        "retire_findings": report_data.get("retire_findings", []),
        "semgrep_findings": report_data.get("semgrep_findings", []),
        "linkfinder_endpoints": report_data.get("linkfinder_endpoints", []),
        "routes": sorted(routes),
        "vite_manifest_sources": vite_sources,
        "out_of_scope": list(dict.fromkeys(out_of_scope)),
        "skipped": skipped,
    }
    results_path = output_dir / "results.json"
    write_results(results_path, results, json_stream)

    # ── Summary ───────────────────────────────────────────────────────────────
    js_files = list(output_dir.rglob("*.js"))
    total_kb = sum(f.stat().st_size for f in js_files) / 1024
    print(f"\n{'─'*55}")
    print(f"{green('[+]')} Done in {results['stats']['elapsed_seconds']:.1f}s — "
          f"{len(js_files)} JS file(s), {total_kb:.1f} KB total")
    # guess_missed is expected (most guessed chunk URLs are probes), not a problem
    real_skips = {k: v for k, v in skipped.items() if v and k != "guess_missed"}
    if real_skips:
        print(f"    Skipped: " + ", ".join(f"{len(v)} {k.replace('_', ' ')}" for k, v in real_skips.items())
              + "  (see results.json)")
    print(f"    Output dir: {output_dir.resolve()}")
    print(f"    Results:    {results_path}")
    print(f"{'─'*55}")
    print(f"{cyan('[Manual step]')} Live source→sink tracing (DOM Invader in Burp Suite) "
          f"isn't automatable — load {args.url} in a Burp-proxied browser with DOM Invader "
          f"enabled and use the beautified JS + endpoints/params above as your map.\n")

    triggered = [f for f in fail_on if hits.get(f)]
    if triggered:
        print(f"{red('[FAIL]')} --fail-on matched: " + ", ".join(f"{f} ({hits[f]})" for f in triggered))
        return 3
    return 0


if __name__ == "__main__":
    main()
