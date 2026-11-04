"""Network & scope: --proxy, --insecure/--ca-cert, --scope/--include-host/--exclude-host, --auth-scope.

Usage: python tests/suite_network_scope.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import contextlib, io, json, os, ssl, stat, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, _REPO)
from js_extractor import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

def run_main(argv):
    """Run cli.main(); return (exit_code, stdout+stderr)."""
    sys.argv = ["js-extractor"] + argv
    buf = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, buf.getvalue()

# ── unit: base_domain / Scope / ScopedAuth ───────────────────────────────────
for host, want in [("app.example.com", "example.com"), ("example.com", "example.com"),
                   ("a.b.example.co.uk", "example.co.uk"), ("shop.example.ac.ir", "example.ac.ir"),
                   ("app.example.ir", "example.ir"), ("10.0.0.5", "10.0.0.5")]:
    check(cli.base_domain(host) == want, f"base_domain({host}) == {want}")
s = cli.Scope("https://app.example.com/", "domain", include=["cdn.partner.net"], exclude=["*.ads.example.com"])
check(s.allows("https://api.example.com/x") and s.allows("https://example.com/"), "scope domain: subdomains + apex allowed")
check(not s.allows("https://evilexample.com/") and not s.allows("https://example.com.evil.io/"), "scope domain: lookalikes rejected")
check(s.allows("https://cdn.partner.net/a.js"), "scope: --include-host")
check(not s.allows("https://x.ads.example.com/"), "scope: --exclude-host wins over domain")
h = cli.Scope("https://app.example.com/", "host")
check(h.allows("https://app.example.com/a") and not h.allows("https://api.example.com/"), "scope host: exact host only")
check(cli.Scope("https://a.b/", "any", exclude=["*.tracker.io"]).restricted, "scope any + exclude counts as restricted")
a = cli.ScopedAuth("https://app.example.com/", {}, {}, mode="domain")
check(a.in_scope("https://api.example.com/") and not a.in_scope("https://cdn.other.com/")
      and not a.in_scope("http://api.example.com/"), "auth-scope domain: subdomains only, https kept")

# ── fake forward proxy serving virtual hosts ─────────────────────────────────
VHOSTS = {
    "app.example.test": {
        "/": ('<html><script src="/app.js"></script>'
              '<script src="http://api.example.test/api.js"></script>'
              '<script src="http://cdn.other.test/lib.js"></script>'
              '<script src="http://ads.tracker.test/t.js"></script>'
              '<script src="/go.js"></script></html>'),
        "/app.js": "var app=1;",
        "/go.js": ("REDIRECT", "http://cdn.other.test/redir.js"),
    },
    "api.example.test": {"/api.js": "var api=1;"},
    "cdn.other.test": {"/lib.js": "var lib=1;", "/redir.js": "var r=1;"},
    "ads.tracker.test": {"/t.js": "var t=1;"},
}
LOG = []   # (host, path, headers)

class Proxy(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urlsplit(self.path)                       # proxies receive absolute URIs
        LOG.append((u.hostname, u.path, dict(self.headers)))
        body = VHOSTS.get(u.hostname, {}).get(u.path)
        if isinstance(body, tuple):
            self.send_response(302); self.send_header("Location", body[1]); self.end_headers(); return
        self.send_response(200 if body else 404); self.end_headers()
        if body: self.wfile.write(body.encode())

proxy_srv = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()
PROXY = f"http://127.0.0.1:{proxy_srv.server_port}"
TARGET = "http://app.example.test/"

def hosts_paths():
    return {(h, p) for h, p, _ in LOG}

# 1. --proxy, scope any: everything goes through the proxy
LOG.clear()
code, out = run_main([TARGET, "--proxy", PROXY, "--no-sourcemaps", "--output-dir", str(TMP / "o1")])
check(code == 0, "proxy: run succeeds")
check({("app.example.test", "/app.js"), ("api.example.test", "/api.js"), ("cdn.other.test", "/lib.js"),
       ("ads.tracker.test", "/t.js"), ("cdn.other.test", "/redir.js")} <= hosts_paths(),
      "proxy: every request (incl. 3rd parties, redirect) went through the proxy")

# 2. --scope domain --exclude-host
LOG.clear()
code, out = run_main([TARGET, "--proxy", PROXY, "--scope", "domain", "--exclude-host", "ads.*",
                      "--no-sourcemaps", "--output-dir", str(TMP / "o2")])
got = hosts_paths()
check(("api.example.test", "/api.js") in got, "scope domain: sibling subdomain fetched")
check(not any(h in ("cdn.other.test", "ads.tracker.test") for h, _ in got),
      f"scope domain: no request to other domains, incl. via redirect ({sorted(got)})")
oos = (TMP / "o2" / "out_of_scope.txt").read_text()
check("cdn.other.test/lib.js" in oos and "ads.tracker.test/t.js" in oos, "scope: out_of_scope.txt lists skipped URLs")
check("Out of scope" in out and "redir.js" in out, "scope: redirect to out-of-scope host blocked and reported")

# 3. --scope host --include-host
LOG.clear()
run_main([TARGET, "--proxy", PROXY, "--scope", "host", "--include-host", "cdn.other.test",
          "--no-sourcemaps", "--output-dir", str(TMP / "o3")])
got = hosts_paths()
check(("cdn.other.test", "/lib.js") in got and not any(h == "api.example.test" for h, _ in got),
      "scope host + include-host: cdn allowed, sibling subdomain blocked")

# 4. --auth-scope
for mode, expect_api in (("host", False), ("domain", True)):
    LOG.clear()
    run_main([TARGET, "--proxy", PROXY, "--cookie", "sid=SECRET", "--auth-scope", mode,
              "--no-sourcemaps", "--output-dir", str(TMP / f"o4{mode}")])
    with_cookie = {h for h, _, hd in LOG if "SECRET" in hd.get("Cookie", "")}
    check("app.example.test" in with_cookie and ("api.example.test" in with_cookie) == expect_api
          and "cdn.other.test" not in with_cookie,
          f"auth-scope {mode}: cookie sent to {sorted(with_cookie)}")

# ── TLS: self-signed HTTPS server ────────────────────────────────────────────
cert, key = TMP / "cert.pem", TMP / "key.pem"
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)

class Https(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = {"/": '<script src="/s.js"></script>', "/s.js": "var s=1;"}.get(self.path)
        self.send_response(200 if body else 404); self.end_headers()
        if body: self.wfile.write(body.encode())

https_srv = ThreadingHTTPServer(("127.0.0.1", 0), Https)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)
threading.Thread(target=https_srv.serve_forever, daemon=True).start()
HTTPS = f"https://127.0.0.1:{https_srv.server_port}/"

code, out = run_main([HTTPS, "--output-dir", str(TMP / "t1")])
check(code == 1 and "--insecure" in out and "--ca-cert" in out, "TLS: self-signed fails by default with a helpful hint")
code, out = run_main([HTTPS, "--insecure", "--output-dir", str(TMP / "t2")])
check(code == 0 and any((TMP / "t2" / "external").glob("*s.js")), "TLS: --insecure works")
check("InsecureRequestWarning" not in out, "TLS: --insecure warning spam suppressed")
code, out = run_main([HTTPS, "--ca-cert", str(cert), "--output-dir", str(TMP / "t3")])
check(code == 0 and any((TMP / "t3" / "external").glob("*s.js")), "TLS: --ca-cert works")

# ── argument validation ──────────────────────────────────────────────────────
code, out = run_main([HTTPS, "--insecure", "--ca-cert", str(cert)])
check(code == 2 and "not both" in out, "validation: --insecure + --ca-cert rejected")
code, out = run_main([HTTPS, "--proxy", "127.0.0.1:8080"])
check(code == 2 and "--proxy must look like" in out, "validation: proxy without scheme rejected")
code, out = run_main([HTTPS, "--ca-cert", str(TMP / "missing.pem")])
check(code == 2 and "not found" in out, "validation: missing CA file rejected")
code, out = run_main(["example.com"])
check(code == 2 and "absolute http(s) URL" in out, "validation: target without scheme rejected")
try:
    import socks  # noqa
    has_socks = True
except ImportError:
    has_socks = False
if not has_socks:
    code, out = run_main([HTTPS, "--proxy", "socks5://127.0.0.1:9050"])
    check(code == 2 and "PySocks" in out, "validation: SOCKS proxy without PySocks gives install hint")

# ── external tools: argv & result filtering ──────────────────────────────────
BIN = TMP / "bin"; BIN.mkdir(); LOGD = TMP / "toollogs"; LOGD.mkdir()
os.environ["PATH"] = f"{BIN}{os.pathsep}{os.environ['PATH']}"
for name, outp in {
    "katana": "",
    "gau": "\n".join(["http://app.example.test/old.js", "http://api.example.test/old2.js",
                       "http://cdn.other.test/x.js"]),
    "httpx": "",
}.items():
    p = BIN / name
    p.write_text(f"#!{sys.executable} -I\nimport sys, json\n"
                 f"open({str(LOGD / name)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
                 f"if {name!r} == 'httpx':\n"
                 f"    [print(json.dumps({{'url': l.strip(), 'status_code': 200}})) for l in sys.stdin]\n"
                 f"else:\n    print({outp!r})\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)

LOG.clear()
run_main([TARGET, "--proxy", PROXY, "--scope", "host", "--katana", "--gau", "--httpx-probe",
          "--no-sourcemaps", "--output-dir", str(TMP / "o5")])
k = json.loads((LOGD / "katana").read_text().splitlines()[-1])
check("-fs" in k and k[k.index("-fs") + 1] == "fqdn" and "-proxy" in k and k[k.index("-proxy") + 1] == PROXY,
      "katana: --scope host → -fs fqdn, --proxy → -proxy")
g = json.loads((LOGD / "gau").read_text().splitlines()[-1])
check("--subs" not in g and "--proxy" not in g, "gau: --scope host drops --subs; archives not proxied")
hx = json.loads((LOGD / "httpx").read_text().splitlines()[-1])
check("-http-proxy" in hx and "-follow-host-redirects" in hx and "-follow-redirects" not in hx,
      "httpx: proxied, same-host redirects only")
alive = (TMP / "o5" / "gau_alive.txt").read_text()
check("app.example.test/old.js" in alive and "api.example.test" not in alive and "cdn.other.test" not in alive,
      "gau results filtered to scope before probing")

LOG.clear()
run_main([TARGET, "--katana", "--gau", "--no-sourcemaps", "--proxy", PROXY, "--output-dir", str(TMP / "o6")])
g = json.loads((LOGD / "gau").read_text().splitlines()[-1])
k = json.loads((LOGD / "katana").read_text().splitlines()[-1])
check("--subs" in g and "-fs" not in k, "defaults unchanged: gau --subs, katana default scope")

# ── --dynamic: proxy, TLS flag, in-browser scope blocking ────────────────────
class PWTimeout(Exception): pass
cli.PlaywrightTimeoutError = PWTimeout
cli.PLAYWRIGHT_OK = True
SEEN = {}
class Req:
    def __init__(self, url): self.url, self.resource_type, self.headers = url, "script", {}
class Route:
    def __init__(self): self.action = None
    def abort(self, *a): self.action = "abort"
    def continue_(self, **kw): self.action = ("continue", kw.get("headers"))
class Page:
    def __init__(self, ctx): self.ctx, self.handlers = ctx, []
    def on(self, ev, fn): self.handlers.append(fn)
    def goto(self, url, **kw):
        for u in ["http://app.example.test/a.js", "http://cdn.other.test/b.js"]:
            r = Req(u)
            for h in self.handlers: h(r)
            route = Route(); self.ctx.handler(route, r); SEEN[u] = route.action
    def wait_for_load_state(self, *a, **kw): pass
    def wait_for_timeout(self, ms): pass
    def evaluate(self, js): return []
class Ctx:
    handler = staticmethod(lambda route, req: route.continue_())
    def add_cookies(self, c): SEEN["cookies"] = c
    def route(self, pat, fn): Ctx.handler = staticmethod(fn)
    def new_page(self): return Page(self)
class Browser:
    def new_context(self, **kw): SEEN["context"] = kw; return Ctx()
    def close(self): pass
class PW:
    def __enter__(self):
        def launch(**kw): SEEN["launch"] = kw; return Browser()
        return type("P", (), {"chromium": type("C", (), {"launch": staticmethod(launch)})})()
    def __exit__(self, *a): return False
cli.sync_playwright = lambda: PW()

args = type("A", (), {"jwt": "TOK", "header": None, "cookie": "sid=1", "proxy": PROXY, "insecure": True,
                      "scope": "host", "include_host": None, "exclude_host": None, "auth_scope": "domain"})()
urls, _ = cli.extract_dynamic(TARGET, args)
check(SEEN["launch"].get("proxy") == {"server": PROXY}, "dynamic: Chromium launched with --proxy")
check(SEEN["context"].get("ignore_https_errors") is True, "dynamic: --insecure → ignore_https_errors")
check(SEEN["http://cdn.other.test/b.js"] == "abort", "dynamic: out-of-scope request aborted in browser")
check(SEEN["http://app.example.test/a.js"][0] == "continue"
      and SEEN["http://app.example.test/a.js"][1].get("Authorization") == "Bearer TOK", "dynamic: in-scope request gets auth")
check(urls == ["http://app.example.test/a.js"], "dynamic: aborted scripts not collected")
check(SEEN["cookies"][0].get("domain") == ".example.test", "dynamic: --auth-scope domain → domain cookie")
args.insecure = False; args.auth_scope = "host"
cli.extract_dynamic(TARGET, args)
check(SEEN["context"].get("ignore_https_errors") is False, "dynamic: TLS verified without --insecure")
check(SEEN["cookies"][0].get("url") == TARGET, "dynamic: --auth-scope host → host-only cookie")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
