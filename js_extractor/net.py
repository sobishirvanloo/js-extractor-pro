"""
HTTP plumbing: auth headers/cookies scoped to the target, request scope, rate limiting,
session construction and fetch() with per-hop scope/auth checks and size caps.
"""
import fnmatch
import hashlib
import ipaddress
import re
import sys
import threading
import time
from urllib.parse import urljoin, urlparse

import requests

from .ui import yellow


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
    except requests.exceptions.HTTPError as e:
        # http_404 / http_410 etc. — lets callers tell "gone" from "broken"
        code = e.response.status_code if e.response is not None else 0
        session.fetch_error = f"http_{code}"
        if not quiet:
            print(f"  {yellow('[WARN]')} Could not fetch {url}: {e}", file=sys.stderr)
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



def looks_like_html(text: str) -> bool:
    """A 'script' that is really an HTML page (soft 404, login redirect, WAF page)."""
    head = text.lstrip("﻿ \t\r\n")[:64].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")

