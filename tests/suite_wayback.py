"""Wayback recovery (--wayback): which scripts count as "gone" (404/410, HTML
instead of JS, httpx-reported dead gau URLs), CDX lookup incl. query-string
fallback, archived copies analysed like the rest, archived source maps,
credentials never sent to the archive, --wayback-max, report output.

Uses a local stand-in for web.archive.org (wayback.WAYBACK_BASE), so no network.

Usage: python tests/suite_wayback.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import contextlib, io, json, os, stat, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(Path(_REPO).resolve()))
from js_extractor import cli
from js_extractor.discovery import wayback  # globals patched below live in this module

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

def serve(handler_fn):
    log = []
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            log.append((self.path, dict(self.headers)))
            code, body = handler_fn(self.path)
            self.send_response(code); self.end_headers()
            if body: self.wfile.write(body.encode())
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_port}", log

# ── the target: some scripts are gone today ──────────────────────────────────
SPA_INDEX = "<!doctype html><html><body>app</body></html>"
TARGET_ROUTES = {
    "/": ('<html><script src="/app.js"></script><script src="/old-bundle.abc.js"></script>'
          '<script src="/spa-old.js"></script><script src="/gone410.js"></script>'
          '<script src="/never-archived.js"></script><script src="/broken.js"></script>'
          '<script src="/cb.js?v=123"></script></html>'),
    "/app.js": (200, 'fetch("/api/v2/current");'),
    "/spa-old.js": (200, SPA_INDEX),             # SPA fallback: HTML instead of JS
    "/gone410.js": (410, ""),
    "/broken.js": (500, ""),                     # server error ≠ gone: no archive lookup
}
def target_handler(path):
    r = TARGET_ROUTES.get(path)
    if r is None:
        return 404, ""
    return (200, r) if isinstance(r, str) else r

TARGET, target_log = serve(target_handler)

# ── stand-in for web.archive.org ─────────────────────────────────────────────
TS = "20230115093000"
ARCHIVE = {   # original URL -> archived body
    f"{TARGET}/old-bundle.abc.js": ('fetch("/api/legacy/admin-export", {method: "POST"});\n'
                                    'const k = "AKIA" + "";\nvar key = "AKIAOLDBUNDLEKEY0001";\n'
                                    '//# sourceMappingURL=old-bundle.abc.js.map'),
    f"{TARGET}/old-bundle.abc.js.map": json.dumps({
        "version": 3, "names": [], "mappings": "AAAA", "sources": ["webpack:///./src/admin.ts"],
        "sourcesContent": ['export const purge = () => fetch("/api/internal/purge-cache");']}),
    f"{TARGET}/spa-old.js": 'fetch("/api/v1/spa-removed");',
    f"{TARGET}/gone410.js": 'fetch("/api/v1/gone-410");\n//# sourceMappingURL=/maps/gone.map',
    f"{TARGET}/maps/gone.map": json.dumps({
        "version": 3, "names": [], "mappings": "AAAA", "sources": ["webpack:///./src/gone.ts"],
        "sourcesContent": ['fetch("/api/internal/from-absolute-map");']}),
    f"{TARGET}/cb.js": 'fetch("/api/v1/cache-busted");',        # archived WITHOUT ?v=123
    f"{TARGET}/gau-old.js": 'fetch("/api/v0/from-gau");',
}
def archive_handler(path):
    u = urlsplit(path)
    if u.path == "/cdx/search/cdx":
        url = parse_qs(u.query)["url"][0]
        if url in ARCHIVE:
            return 200, json.dumps([["timestamp", "original"], ["20200101000000", url], [TS, url]])
        return 200, "[]"
    if u.path.startswith("/web/"):
        rest = unquote(path[len("/web/"):])
        ts, _, original = rest.partition("id_/")
        body = ARCHIVE.get(original)
        return (200, body) if body is not None else (404, "")
    return 404, ""

WAYBACK, wb_log = serve(archive_handler)
wayback.WAYBACK_BASE = WAYBACK
wayback.WAYBACK_RATE = 0          # no throttling against the local stand-in

def run_main(argv):
    sys.argv = ["js-extractor"] + argv
    buf = io.StringIO(); code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, buf.getvalue()

COMMON = ["--rate-limit", "0", "--no-chunks", "--endpoints", "--secrets"]

# ── unit ─────────────────────────────────────────────────────────────────────
s = cli.make_wayback_session()
check(not s.proxies and s.auth is None and s.scope is None, "wayback session: no proxy, no target auth, no target scope")
check(cli.wayback_latest_snapshot(f"{TARGET}/old-bundle.abc.js", s) == (TS, f"{TARGET}/old-bundle.abc.js"),
      "CDX: newest 200 snapshot chosen")
check(cli.wayback_latest_snapshot(f"{TARGET}/nope.js", s) is None, "CDX: not archived → None")

# ── 1. without --wayback: only a hint ────────────────────────────────────────
wb_log.clear()
code, out = run_main([TARGET + "/", "--output-dir", str(TMP / "off")] + COMMON)
res = json.loads((TMP / "off" / "results.json").read_text())
check(code == 0 and not wb_log, "without --wayback: archive never contacted")
check(res["stats"]["wayback"]["candidates"] == 5 and "add --wayback" in out,
      f"dead scripts counted (404, 410, HTML-instead-of-JS; not 500) + hint ({res['stats']['wayback']})")

# ── 2. with --wayback ────────────────────────────────────────────────────────
wb_log.clear()
code, out = run_main([TARGET + "/", "--wayback", "--cookie", "sid=SECRETCOOKIE", "--jwt", "SECRETJWT",
                      "--scope", "host", "--report", "--output-dir", str(TMP / "on")] + COMMON)
res = json.loads((TMP / "on" / "results.json").read_text())
got = {a["url"].replace(TARGET, "") for a in res["archived"]}
check(got == {"/old-bundle.abc.js", "/spa-old.js", "/gone410.js", "/cb.js?v=123"},
      f"archived copies recovered (404, HTML fallback, 410, query-string fallback): {sorted(got)}")
check(not any("never-archived" in a["url"] for a in res["archived"]), "never-archived script: no copy, no crash")
check(all(a["snapshot"] == TS for a in res["archived"]), "newest snapshot used")
check(all((TMP / "on" / a["saved_path"]).exists() and a["saved_path"].startswith("archived/") for a in res["archived"]),
      "archived files saved under archived/")
for ep in ("/api/legacy/admin-export", "/api/v1/spa-removed", "/api/v1/gone-410", "/api/v1/cache-busted"):
    check(ep in res["endpoints"], f"endpoint only in an archived bundle found: {ep}")
check("/api/internal/purge-cache" in res["endpoints"], "archived source map → recovered original source analysed")
check("/api/internal/from-absolute-map" in res["endpoints"],
      "absolute sourceMappingURL (/maps/x.map) resolved against the ORIGINAL site, fetched from the archive")
legacy = next(d for d in res["endpoint_details"] if d["path"] == "/api/legacy/admin-export")
check(legacy["methods"] == ["POST"] and legacy["hidden"] and legacy["file"].startswith("archived/"),
      "archived endpoint keeps method, hidden flag and archived/ location")
sec = [x for x in res["secrets"] if x["value"] == "AKIAOLDBUNDLEKEY0001"]
check(sec and sec[0]["file"].startswith("archived/"), "secret in an archived bundle found, located in archived/")
check(res["stats"]["wayback"] == {"candidates": 5, "found": 4}, f"wayback stats {res['stats']['wayback']}")
leak = [p for p, h in wb_log if "SECRET" in json.dumps(h)]
check(wb_log and not leak, "target cookie/JWT never sent to the archive")
check(wb_log, "--scope host does not block the archive (scope applies to the target)")
check(not any("/broken.js" in p for p, _ in wb_log), "500 error is not treated as 'gone'")
rep = (TMP / "on" / "report.html").read_text()
check("archived" in rep and f"snapshot {TS}" in rep, "report lists archived files with snapshot link")

# ── 3. --wayback-max ─────────────────────────────────────────────────────────
wb_log.clear()
run_main([TARGET + "/", "--wayback", "--wayback-max", "1", "--output-dir", str(TMP / "max")] + COMMON)
res = json.loads((TMP / "max" / "results.json").read_text())
cdx_lookups = {parse_qs(urlsplit(p).query)["url"][0].split("?")[0] for p, _ in wb_log if p.startswith("/cdx/")}
check(len(res["archived"]) == 1 and len(cdx_lookups) == 1, f"--wayback-max 1: one script looked up ({cdx_lookups})")
code, out = run_main([TARGET + "/", "--wayback-max", "0"])
check(code == 2, "--wayback-max 0 rejected")

# ── 4. gau URLs that httpx reports dead are seeds too ────────────────────────
BIN = TMP / "bin"; BIN.mkdir()
os.environ["PATH"] = f"{BIN}{os.pathsep}{os.environ['PATH']}"
for name, body in {
    "gau": f"print({TARGET + '/gau-old.js'!r})",
    "httpx": "import sys, json\n[print(json.dumps({'url': l.strip(), 'status_code': 404})) for l in sys.stdin]",
}.items():
    p = BIN / name
    p.write_text(f"#!{sys.executable} -I\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
run_main([TARGET + "/", "--gau", "--httpx-probe", "--wayback", "--output-dir", str(TMP / "gau")] + COMMON)
res = json.loads((TMP / "gau" / "results.json").read_text())
check(any(a["url"].endswith("/gau-old.js") for a in res["archived"]) and "/api/v0/from-gau" in res["endpoints"],
      "gau URL that httpx reports 404 → recovered from the archive")
check(sum(1 for a in res["archived"] if a["url"].endswith("/gau-old.js")) == 1, "no duplicate lookups for the same dead URL")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
