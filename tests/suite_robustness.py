"""Robustness: timeouts keep partial output, wappalyzer/dynamic
crashes, param noise, inline worker/import discovery, per-file secrets.

Usage: python tests/suite_robustness.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import json, os, stat, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, _REPO)
from js_extractor import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
BIN = TMP / "bin"; BIN.mkdir()
os.environ["PATH"] = f"{BIN}{os.pathsep}{os.environ['PATH']}"

fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

def fake_tool(name, body):
    p = BIN / name
    p.write_text(f"#!{sys.executable} -I\nimport sys, time, json\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)

# ── (a) timeouts keep partial output ─────────────────────────────────────────
fake_tool("katana", """
for u in ["https://t/a.js", "https://t/b.js?v=1", "https://t/page.html"]:
    print(u, flush=True)
sys.stdout.write("https://t/trunc"); sys.stdout.flush()   # incomplete line
time.sleep(30)""")
t0 = time.time()
js = cli.run_katana("https://t/", timeout=2)
check(time.time() - t0 < 10, "katana: timeout honoured")
check(js == ["https://t/a.js", "https://t/b.js?v=1"], f"katana: partial .js results kept, truncated line dropped ({js})")

fake_tool("gau", """
for i in range(3): print(f"https://t/old{i}.js", flush=True)
time.sleep(30)""")
check(len(cli.run_gau("t", timeout=2)) == 3, "gau: partial results kept on timeout")

fake_tool("httpx", """
for l in sys.stdin:
    print(json.dumps({"url": l.strip(), "status_code": 200}), flush=True)
    break
time.sleep(30)""")
alive = cli.run_httpx_probe(["https://t/1.js", "https://t/2.js"], timeout=2)
check([a["url"] for a in alive] == ["https://t/1.js"], "httpx: partial JSON lines kept on timeout")

# ── (b) wappalyzer output shapes ─────────────────────────────────────────────
fake_tool("wappalyzer", """print(json.dumps([{"name": "Nginx", "version": "1.2", "categories": ["Web servers"]},
                                  {"name": "React", "categories": [{"name": "JS frameworks"}]}, "junk"]))""")
techs = cli.run_wappalyzer("https://t/")
check([t["name"] for t in techs] == ["Nginx", "React"], "wappalyzer: bare list output no longer crashes")
check(techs[0]["categories"] == ["Web servers"] and techs[1]["categories"] == ["JS frameworks"],
      "wappalyzer: string and dict categories both handled")
fake_tool("wappalyzer", 'print(json.dumps({"technologies": [{"name": "Vue", "version": None}]}))')
check(cli.run_wappalyzer("https://t/") == [{"name": "Vue", "version": "", "categories": []}], "wappalyzer: dict output still works")

# ── (b) --dynamic failures don't crash ───────────────────────────────────────
class PWTimeout(Exception): pass
cli.PlaywrightTimeoutError = PWTimeout
cli.PLAYWRIGHT_OK = True

def make_pw(goto_raises=None, idle_raises=False, launch_raises=None):
    class Page:
        def __init__(self): self.handlers = []
        def on(self, ev, fn): self.handlers.append(fn)
        def goto(self, url, **kw):
            for h in self.handlers:
                h(type("R", (), {"resource_type": "script", "url": "https://t/early.js"})())
            if goto_raises: raise goto_raises
        def wait_for_load_state(self, state, **kw):
            if idle_raises: raise PWTimeout("idle")
        def wait_for_timeout(self, ms):
            for h in self.handlers:
                h(type("R", (), {"resource_type": "script", "url": "https://t/late.js"})())
        def evaluate(self, js): return ["  var inl = 1;  "]
    class Ctx:
        def add_cookies(self, c): pass
        def route(self, *a): pass
        def new_page(self): return Page()
    class Browser:
        closed = False
        def new_context(self, **kw): return Ctx()
        def close(self): Browser.closed = True
    class PW:
        def __enter__(self):
            if launch_raises: raise launch_raises
            return type("P", (), {"chromium": type("C", (), {"launch": staticmethod(lambda **kw: Browser())})})()
        def __exit__(self, *a): return False
    return (lambda: PW()), Browser

args = type("A", (), {"jwt": "", "header": None, "cookie": ""})()
cli.sync_playwright, B = make_pw(idle_raises=True)
urls, inl = cli.extract_dynamic("https://t/", args)
check(urls == ["https://t/early.js", "https://t/late.js"], "dynamic: networkidle timeout → continues; late chunks captured")
check(inl == ["var inl = 1;"], "dynamic: inline blocks stripped (dedupe with static)")
cli.sync_playwright, B = make_pw(goto_raises=PWTimeout("load"))
urls, _ = cli.extract_dynamic("https://t/", args)
check("https://t/early.js" in urls, "dynamic: load timeout → keeps what loaded")
cli.sync_playwright, B = make_pw(goto_raises=RuntimeError("net::ERR_NAME_NOT_RESOLVED"))
urls, _ = cli.extract_dynamic("https://t/", args)
check(urls == ["https://t/early.js"] and B.closed, "dynamic: navigation error → no crash, browser closed")
cli.sync_playwright, B = make_pw(launch_raises=RuntimeError("Executable doesn't exist"))
check(cli.extract_dynamic("https://t/", args) == ([], []), "dynamic: Chromium missing → no crash")

# ── (c) param noise ──────────────────────────────────────────────────────────
params = cli.extract_params("x = {toString: 1, forEach: 2, hasOwnProperty: 3, userId: 4, ToString: 5}")
check("userId" in params and not {"toString", "forEach", "ToString"} & set(params), f"params: mixed-case noise filtered ({params})")

# ── (d) + (e): full run against a local server ───────────────────────────────
PAD = "\n".join(f"var pad{i} = {i};" for i in range(20))
JWT1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJlb25lMTIz"
JWT2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMiJ9.c2lnbmF0dXJldHdvNDU2"
app_js = f'{PAD}\nconst AWS = "AKIAEXTERNALFILE0001";\nconst t1 = "{JWT1}";\nconst t2 = "{JWT2}";\n//# sourceMappingURL=app.js.map'
src_ts = 'const unused = 0;\nconst AWS = "AKIAEXTERNALFILE0001";\nconst pwd = { password: "hunter2x" };'
routes = {
    "/": ("<html><script>navigator.serviceWorker.register('/sw.js');</script>"
          "<script type='module'>import { a } from './mod.js';</script>"
          "<script>var x = 1;\nvar y = 2;\nvar inl = { api_key: 'INLINEKEY0123456789' };</script>"
          "<script src='/app.js'></script></html>"),
    "/app.js": app_js,
    "/app.js.map": json.dumps({"version": 3, "names": [], "mappings": "AAAA",
                               "sources": ["webpack:///./src/keys.ts"], "sourcesContent": [src_ts]}),
    "/sw.js": "self.addEventListener('fetch', e => {});",
    "/mod.js": "export const a = 1;",
}
HITS = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        b = routes.get(self.path)
        self.send_response(200 if b is not None else 404); self.end_headers()
        if b is not None: self.wfile.write(b.encode())
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
OUT = TMP / "out"
sys.argv = ["js-extractor", f"http://127.0.0.1:{srv.server_port}/", "--secrets", "--report",
            "--output-dir", str(OUT)]
cli.main()

check("/sw.js" in HITS, "inline: service worker registered in inline script is fetched")
check("/mod.js" in HITS, "inline: module import in inline script is fetched")
check(any("sw.js" in p.name for p in (OUT / "external").iterdir()), "inline: worker saved to external/")

secrets = json.loads((OUT / "secrets.json").read_text())
by_val = {s["value"]: s for s in secrets}

def line_on_disk(loc):
    return (OUT / loc["file"]).read_text().splitlines()[loc["line"] - 1]

all_ok = all(s["value"] in line_on_disk(l) for s in secrets for l in s["locations"])
check(secrets and all_ok, f"secrets: every file:line points at the real line on disk ({len(secrets)} findings)")
aws = by_val.get("AKIAEXTERNALFILE0001")
check(aws and {l["file"].split("/")[0] for l in aws["locations"]} == {"external", "sourcemap_recovered"},
      "secrets: same key in bundle + recovered source grouped into one finding with 2 locations")
check(JWT1 in by_val and JWT2 in by_val, "secrets: distinct JWTs with same header no longer collapsed")
check("INLINEKEY0123456789" in by_val and by_val["INLINEKEY0123456789"]["file"].startswith("inline/"),
      "secrets: inline finding attributed to inline/ file")
check("hunter2x" in by_val and by_val["hunter2x"]["file"].endswith("keys.ts"), "secrets: recovered source attributed to its file")

report = (OUT / "report.html").read_text()
check("AKIAEXTERNALFILE0001" not in report and "hunter2x" not in report and JWT1 not in report,
      "report: secret values masked")
check("keys.ts:3" in report and "external/" in report, "report: shows file:line locations")
for v in ("hunter2x", "INLINEKEY0123456789", JWT1):
    m = cli.mask_secret(v)
    check(len(m.replace("...", "")) <= len(v) // 2, f"mask_secret reveals at most half: {m!r}")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
