"""Source map recovery.

Usage: python tests/suite_sourcemap.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import base64, json, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, _REPO)
from jxray import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
OUT = TMP / "out"
HITS = []


def smap(sources, contents, **extra):
    return json.dumps({"version": 3, "sources": sources, "sourcesContent": contents,
                       "names": [], "mappings": "AAAA", **extra})


inline_map = smap(["src/inline.ts"], ["export const inlined = 1;"])
b64 = base64.b64encode(inline_map.encode()).decode().rstrip("=")   # unpadded, as some bundlers emit

routes = {
    # 1. classic comment, real content incl. a .vue file that must NOT be JS-beautified
    "/a.js": (200, {}, "var a=1;\n//# sourceMappingURL=a.js.map"),
    "/a.js.map": (200, {}, smap(["webpack:///./src/App.vue", "webpack:///./src/index.js", "webpack:///./src/api.js"],
                                ["<template><div/></template>", "import App from './App.vue';", None])),
    # 2. only the HTTP header points at the map; XSSI prefix + sourceRoot
    "/b.js": (200, {"SourceMap": "/maps/b.map"}, "var b=1;"),
    "/maps/b.map": (200, {}, ")]}'\n" + smap(["index.js"], ["const fromHeader = 1;"], sourceRoot="pkg/")),
    # 3. no reference at all — must be found by guessing c.js.map (query string stripped)
    "/c.js": (200, {}, "var c=1;"),
    "/c.js.map": (200, {}, smap(["src/index.js"], ["const guessed = 1;"])),
    # 4. inline base64 data: URI, block-comment style
    "/d.js": (200, {}, f"var d=1;\n/*# sourceMappingURL=data:application/json;charset=utf-8;base64,{b64} */"),
    # 5. index map with sections
    "/e.js": (200, {}, "var e=1;\n//# sourceMappingURL=e.js.map"),
    "/e.js.map": (200, {}, json.dumps({"version": 3, "sections": [
        {"offset": {"line": 0, "column": 0}, "map": json.loads(smap(["sec/one.js"], ["one()"]))},
        {"offset": {"line": 9, "column": 0}, "map": json.loads(smap(["sec/two.js"], ["two()"]))}]})),
    # 6. guess hits a soft-404 HTML page — must stay silent, recover nothing
    "/f.js": (200, {}, "var f=1;"),
    "/f.js.map": (200, {"Content-Type": "text/html"}, "<html>Not found</html>"),
    # 7. multiple comments: the LAST one wins
    "/g.js": (200, {}, "//# sourceMappingURL=wrong.map\nvar g=1;\n//# sourceMappingURL=g.js.map"),
    "/g.js.map": (200, {}, smap(["src/index.js"], ["const right = 1;"])),
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        r = routes.get(self.path.split("?")[0])
        if not r:
            self.send_response(404); self.end_headers(); return
        status, headers, body = r
        self.send_response(status)
        for k, v in headers.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body.encode())


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_port}"
session = cli.requests.Session()

fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

def run(path, **kw):
    url = BASE + path
    resp = cli.fetch(url, session)
    n = cli.try_recover_sourcemap(resp.text, url, session, OUT, headers=resp.headers, **kw)
    bundle = OUT / "sourcemap_recovered" / cli.safe_filename(url, prefix="map")[:-3]
    return n, bundle

# --- unit: parser ---
check(cli.parse_sourcemap(")]}'\n" + smap(["x.js"], ["1"])) == [("x.js", "1")], "parser: XSSI prefix")
check(cli.parse_sourcemap(smap(["x.js", "y.js"], ["1"])) == [("x.js", "1"), ("y.js", None)], "parser: missing sourcesContent -> None")
check(cli.parse_sourcemap(smap(["x.js"], ["1"], sourceRoot="root/")) == [("root/x.js", "1")], "parser: sourceRoot applied")
check(cli.parse_sourcemap(smap(["http://h/x.js"], ["1"], sourceRoot="root/")) == [("http://h/x.js", "1")], "parser: sourceRoot not applied to absolute URL")
try:
    cli.parse_sourcemap("<html>"); check(False, "parser: rejects HTML")
except ValueError:
    check(True, "parser: rejects HTML")

# --- integration ---
n, b = run("/a.js")
check(n == 2, f"comment ref: recovered 2 of 3 (got {n})")
check((b / "webpack_/src/App.vue").read_text() == "<template><div/></template>", ".vue written verbatim (not JS-beautified)")
idx = (b / "_sources.txt").read_text()
check("[no-content]" in idx and "src/api.js" in idx, "_sources.txt lists source without content")

n, b = run("/b.js")
check(n == 1 and (b / "pkg/index.js").read_text() == "const fromHeader = 1;", "SourceMap header + XSSI + sourceRoot")

n, b = run("/c.js?v=123")
check(n == 1 and (b / "src/index.js").read_text() == "const guessed = 1;", "guessed <script>.map (query stripped)")

hits_before = len(HITS)
n, b = run("/c.js", guess=False)
check(n == 0 and HITS[hits_before:] == ["/c.js"], "guess=False does not probe .map")

n, b = run("/d.js")
check(n == 1 and (b / "src/inline.ts").read_text() == "export const inlined = 1;", "inline base64 data: URI (unpadded, /* */ comment)")

n, b = run("/e.js")
check(n == 2 and (b / "sec/one.js").exists() and (b / "sec/two.js").exists(), "index map with sections")

n, b = run("/f.js")
check(n == 0 and not b.exists(), "soft-404 on guessed map: nothing written")

n, b = run("/g.js")
check(n == 1 and (b / "src/index.js").read_text() == "const right = 1;" and "/wrong.map" not in HITS, "last sourceMappingURL wins")

# collision: a.js and g.js both have src/index.js-like paths; c.js and g.js both have src/index.js
c_b = OUT / "sourcemap_recovered" / cli.safe_filename(BASE + "/c.js?v=123", prefix="map")[:-3]
check((c_b / "src/index.js").read_text() == "const guessed = 1;", "same-named sources from different bundles don't overwrite each other")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
