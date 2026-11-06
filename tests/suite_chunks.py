"""Lazy chunk discovery: lazy chunk discovery for webpack (CRA/inline runtime, nested
.e() ids), Next.js (_buildManifest via buildId), Vite (modulepreload, preload
deps, .vite/manifest.json), --no-chunks, SPA index.html fallback handling.

Usage: python tests/suite_chunks.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import contextlib, io, json, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(Path(_REPO).resolve()))
from jxray import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

def serve(routes, spa_fallback=True):
    """Static server; unknown paths get index.html with 200, like SPA hosting."""
    hits = []
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            path = self.path.split("?")[0]
            hits.append(path)
            body = routes.get(path)
            if body is None and spa_fallback:
                body = routes["/"]
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type", "text/html" if body and body.lstrip().startswith("<") else "application/javascript")
            self.end_headers()
            if body is not None:
                self.wfile.write(body.encode())
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_port}", hits

def run_main(argv):
    sys.argv = ["jxray"] + argv
    buf = io.StringIO(); code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, buf.getvalue()

def results(d):
    return json.loads((TMP / d / "results.json").read_text())

def fetched(res):
    return {f["url"].split("/", 3)[3] for f in res["files"] if f["kind"] == "external"}

COMMON = ["--rate-limit", "0", "--no-sourcemaps", "--endpoints"]

# ── 1. CRA: inline runtime chunk + contenthash map ───────────────────────────
cra_index = ('<!doctype html><html><body><div id="root"></div>'
             '<script>!function(){var n={};n.p="/",n.u=function(e){return"static/js/"+e+"."'
             '+{17:"a1b2c3",42:"d4e5f6",55:"dead00"}[e]+".chunk.js"}}();</script>'
             '<script src="/static/js/main.abc.js"></script></body></html>')
CRA, cra_hits = serve({
    "/": cra_index,
    "/static/js/main.abc.js": 'Promise.all([n.e(17)]).then(n.bind(n,1));',
    "/static/js/17.a1b2c3.chunk.js": 'fetch("/api/internal/reports");',
    "/static/js/42.d4e5f6.chunk.js": 'fetch("/api/admin/settings");',
    # 55 is listed in the map but not deployed → SPA fallback returns index.html
})
code, out = run_main([CRA + "/", "--output-dir", str(TMP / "cra")] + COMMON)
r = results("cra")
got = fetched(r)
check({"static/js/17.a1b2c3.chunk.js", "static/js/42.d4e5f6.chunk.js"} <= got,
      "CRA: chunks from the INLINE runtime's hash map downloaded (incl. 42, never referenced)")
check("/api/admin/settings" in r["endpoints"], "CRA: endpoint only present in a lazy chunk is found")
check(any(u.endswith("55.dead00.chunk.js") for u in r["skipped"]["guess_missed"])
      and "static/js/55.dead00.chunk.js" not in got, "CRA: SPA index.html fallback for a missing chunk → guess_missed, not saved")
check(r["stats"]["chunks"]["found"] == 2 and r["stats"]["chunks"]["webpack_runtimes"] >= 1,
      f"CRA: chunk stats {r['stats']['chunks']}")
check("Could not fetch" not in out and "returned an HTML page" not in out, "CRA: guessed misses are quiet")
check("guess missed" not in out, "CRA: guess misses not reported as 'Skipped' in the summary")

# ── 2. Next.js: buildId → unreferenced _buildManifest.js → page chunks + routes
next_index = ('<html><body><div id="__next"></div>'
              '<script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/","buildId":"BLD42"}</script>'
              '<script src="/_next/static/chunks/webpack-111.js"></script>'
              '<script src="/_next/static/chunks/main-222.js"></script></body></html>')
NEXT, next_hits = serve({
    "/": next_index,
    "/_next/static/chunks/webpack-111.js":
        'r.u=function(e){return 2272===e?"static/chunks/2272-ff00.js":"static/chunks/"+(({261:"player"})[e]||e)'
        '+"."+({261:"bb22",777:"cc33"})[e]+".js"},r.p="/_next/";',
    "/_next/static/chunks/main-222.js": "var main=1;",
    "/_next/static/BLD42/_buildManifest.js":
        'self.__BUILD_MANIFEST={__rewrites:{afterFiles:[]},"/":["static/chunks/pages/index-aa.js"],'
        '"/admin/users":["static/chunks/pages/admin/users-bb.js"],"/_error":["static/chunks/pages/_error-cc.js"]};',
    "/_next/static/chunks/pages/index-aa.js": "var idx=1;",
    "/_next/static/chunks/pages/_error-cc.js": "var err=1;",
    "/_next/static/chunks/pages/admin/users-bb.js": 'fetch("/api/admin/users/export");',
    "/_next/static/chunks/2272-ff00.js": "var fixed=1;",
    "/_next/static/chunks/player.bb22.js": "var p=1;",
    "/_next/static/chunks/777.cc33.js": 'fetch("/api/v2/billing");',
})
code, out = run_main([NEXT + "/", "--output-dir", str(TMP / "next")] + COMMON)
r = results("next")
got = fetched(r)
check("_next/static/BLD42/_buildManifest.js" in got, "Next: unreferenced _buildManifest.js found via buildId in __NEXT_DATA__")
check({"_next/static/chunks/pages/admin/users-bb.js", "_next/static/chunks/pages/_error-cc.js"} <= got,
      "Next: page chunks from the build manifest downloaded")
check("/admin/users" in r["routes"] and (TMP / "next" / "routes.txt").exists(), "Next: routes recovered → routes.txt")
check({"_next/static/chunks/player.bb22.js", "_next/static/chunks/777.cc33.js"} <= got,
      "Next: webpack runtime chunks (names map + hash map) downloaded")
check("/api/admin/users/export" in r["endpoints"] and "/api/v2/billing" in r["endpoints"],
      "Next: endpoints from lazy page chunks found")

# ── 3. Vite: modulepreload + __vitePreload deps + public .vite/manifest.json ──
vite_index = ('<html><head><script type="module" src="/assets/index-Ab12.js"></script>'
              '<link rel="modulepreload" href="/assets/vendor-Cd34.js"></head><body></body></html>')
VITE, vite_hits = serve({
    "/": vite_index,
    "/assets/index-Ab12.js": ('const A=()=>__vitePreload(()=>import("./Admin-Ef56.js"),["assets/Admin-Ef56.js",'
                              '"assets/Admin-Ef56.css","assets/Shared-Gh78.js"]);'),
    "/assets/vendor-Cd34.js": "var vendor=1;",
    "/assets/Admin-Ef56.js": 'fetch("/api/vite/admin");',
    "/assets/Shared-Gh78.js": "var shared=1;",
    "/assets/Hidden-Zz99.js": 'fetch("/api/vite/hidden-only-in-manifest");',
    "/.vite/manifest.json": json.dumps({
        "src/main.ts": {"file": "assets/index-Ab12.js", "isEntry": True},
        "src/pages/Hidden.vue": {"file": "assets/Hidden-Zz99.js", "isDynamicEntry": True},
        "src/style.css": {"file": "assets/style-1.css"}}),
})
code, out = run_main([VITE + "/", "--output-dir", str(TMP / "vite")] + COMMON)
r = results("vite")
got = fetched(r)
check("assets/vendor-Cd34.js" in got, "Vite: <link rel=modulepreload> script downloaded")
check({"assets/Admin-Ef56.js", "assets/Shared-Gh78.js"} <= got, "Vite: preload dependency chunks downloaded")
check("assets/Hidden-Zz99.js" in got and "/api/vite/hidden-only-in-manifest" in r["endpoints"],
      "Vite: chunk listed only in public .vite/manifest.json downloaded")
check("src/pages/Hidden.vue" in r["vite_manifest_sources"], "Vite: original source paths from the manifest recorded")
check(not any(u.endswith(".css") for u in fetched(r)), "Vite: CSS entries not fetched as scripts")

# ── 4. Nested discovery: ids only from .e() calls, spread across waves ───────
NEST, nest_hits = serve({
    "/": '<html><script src="/js/runtime.js"></script><script src="/js/app.js"></script></html>',
    "/js/runtime.js": '__webpack_require__.p = "/js/";\n__webpack_require__.u = (chunkId) => { return "" + chunkId + ".js"; };',
    "/js/app.js": '__webpack_require__.e("src_pages_a").then(()=>1);',
    "/js/src_pages_a.js": '__webpack_require__.e("src_pages_b");',
    "/js/src_pages_b.js": '__webpack_require__.e("src_pages_c"); fetch("/api/deep/b");',
    "/js/src_pages_c.js": 'fetch("/api/deep/c");',
})
code, out = run_main([NEST + "/", "--output-dir", str(TMP / "nest")] + COMMON)
r = results("nest")
check({"js/src_pages_a.js", "js/src_pages_b.js", "js/src_pages_c.js"} <= fetched(r),
      "nested: chunk → chunk → chunk discovered across waves (ids from .e() calls)")
check("/api/deep/c" in r["endpoints"], "nested: endpoint 3 levels deep found")

# ── 5. --no-chunks turns it all off ──────────────────────────────────────────
cra_hits.clear()
run_main([CRA + "/", "--no-chunks", "--output-dir", str(TMP / "off")] + COMMON)
r = results("off")
check(not any("chunk" in u for u in fetched(r)) and "/.vite/manifest.json" not in cra_hits
      and r["stats"]["chunks"]["candidates"] == 0, "--no-chunks: no chunk guesses, no manifest probes")

# ── 6. --max-files still bounds chunk downloads ─────────────────────────────
run_main([NEXT + "/", "--max-files", "4", "--output-dir", str(TMP / "cap")] + COMMON)
check(len(fetched(results("cap"))) <= 4, "--max-files bounds chunk discovery too")

# ── 7. report shows routes, escaped ──────────────────────────────────────────
run_main([NEXT + "/", "--report", "--output-dir", str(TMP / "rep")] + COMMON)
rep = (TMP / "rep" / "report.html").read_text()
check("Routes &amp; Lazy Chunks" in rep or "Routes & Lazy Chunks" in rep, "report: routes section present")
check("/admin/users" in rep, "report: recovered routes listed")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
