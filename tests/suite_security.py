"""Security regressions: source map path traversal, report XSS, credential scoping.

Usage: python tests/suite_security.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import json, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, _REPO)
from js_extractor import cli

LOG = {"target": [], "third": []}
TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
OUT = TMP / "out"
ESCAPE_TARGET = TMP / "pwned.txt"   # traversal tries to write here


def make_handler(name, routes):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            LOG[name].append((self.path, dict(self.headers)))
            r = routes.get(self.path)
            if r is None:
                self.send_response(404); self.end_headers(); return
            status, headers, body = r()
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())
    return H


third = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("third", {
    "/cdn.js": lambda: (200, {}, "var cdn=1;"),
    "/redirected.js": lambda: (200, {}, "var r=1;"),
}))
P3 = third.server_port
THIRD = f"http://localhost:{P3}"   # hostname differs from the target's

depth = len(OUT.resolve().parts) + 3
traversal = "webpack:///" + "../" * depth + str(ESCAPE_TARGET).lstrip("/")
smap = json.dumps({
    "version": 3, "sources": [traversal, "webpack:///./src/ok.js", "..\\..\\win.js"],
    "sourcesContent": ["PWNED", "var ok=1;", "var w=1;"], "names": [], "mappings": "AAAA",
})

target_routes = {
    "/": lambda: (200, {"Content-Type": "text/html"},
                  f'<html><script src="/app.js"></script><script src="{THIRD}/cdn.js"></script>'
                  f'<script src="/redir.js"></script></html>'),
    "/app.js": lambda: (200, {}, 'fetch("/api/<img src=x onerror=alert(1)>");\n'
                                 'var o={"<script>alert(2)</script>":1};\n'
                                 '//# sourceMappingURL=/app.js.map'),
    "/app.js.map": lambda: (200, {}, smap),
    "/redir.js": lambda: (302, {"Location": f"{THIRD}/redirected.js"}, ""),
}
target = ThreadingHTTPServer(("127.0.0.1", 0), make_handler("target", target_routes))
for s in (third, target):
    threading.Thread(target=s.serve_forever, daemon=True).start()
TARGET = f"http://127.0.0.1:{target.server_port}/"


sys.argv = ["js-extractor", TARGET, "--cookie", "session=SECRETCOOKIE",
            "--jwt", "SECRETJWT", "--header", "X-Api-Key: SECRETKEY",
            "--endpoints", "--params", "--report", "--output-dir", str(OUT)]
cli.main()

fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

# 1. traversal
check(not ESCAPE_TARGET.exists(), "source map traversal did not escape output dir")
rec = OUT / "sourcemap_recovered"
written = sorted(str(p.relative_to(rec)) for p in rec.rglob("*") if p.is_file())
print("     recovered files:", written)
check(all(p.resolve().is_relative_to(rec.resolve()) for p in rec.rglob("*")), "all recovered files inside sourcemap_recovered/")
check(any(w.endswith("ok.js") for w in written), "legit source still recovered")

# 2. report XSS
report = (OUT / "report.html").read_text()
check("<img src=x" not in report and "<script>alert" not in report, "no raw attacker HTML in report")
check("&lt;img src=x onerror=alert(1)&gt;" in report, "attacker endpoint shown escaped")
check("Content-Security-Policy" in report, "report has CSP")

# 3. credential scoping
secrets = ("SECRETCOOKIE", "SECRETJWT", "SECRETKEY")
leaked = [(p, h) for p, h in LOG["third"] if any(s in json.dumps(h) for s in secrets)]
check(LOG["third"] and not leaked, f"no credentials sent to third party ({len(LOG['third'])} requests: {[p for p,_ in LOG['third']]})")
t_hdrs = [h for p, h in LOG["target"] if p == "/app.js"][0]
check("SECRETCOOKIE" in t_hdrs.get("Cookie", "") and t_hdrs.get("Authorization") == "Bearer SECRETJWT"
      and t_hdrs.get("X-Api-Key") == "SECRETKEY", "target host still receives cookie + JWT + custom header")
check(any(p == "/redirected.js" for p, _ in LOG["third"]), "cross-host redirect still followed")

# unit: ScopedAuth edge cases
sa = cli.ScopedAuth("https://app.example.com/x", {"A": "1"}, {})
check(sa.in_scope("https://app.example.com/y") and sa.in_scope("https://APP.example.com:443/z"), "scope: same host matches")
for u in ("https://evil.example.com/", "https://app.example.com.evil.io/", "http://app.example.com/",
          "https://example.com/", "https://sub.app.example.com/"):
    check(not sa.in_scope(u), f"scope: rejects {u}")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
