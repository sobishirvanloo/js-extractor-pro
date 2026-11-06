"""Analysis coverage: analyses must cover inline/ and sourcemap_recovered/, not just external/.

Usage: python tests/suite_analysis_coverage.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import json, os, stat, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, _REPO)
from jxray import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
OUT, BIN, LOGS = TMP / "out", TMP / "bin", TMP / "logs"
BIN.mkdir(); LOGS.mkdir()

# --- fake external tools: log argv, emit valid empty JSON ---
fake = {
    "retire":     '{"data": []}',
    "semgrep":    '{"results": []}',
    "linkfinder": "",
}
for name, out in fake.items():
    p = BIN / name
    p.write_text(f"""#!{sys.executable} -I
import json, sys
with open({str(LOGS / name)!r}, "a") as f: f.write(json.dumps(sys.argv[1:]) + "\\n")
print({out!r})
""")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
os.environ["PATH"] = f"{BIN}{os.pathsep}{os.environ['PATH']}"

app_src = '''export async function loadUsers() {
  return fetch("/api/internal/recovered-users?tenantId=1");
}
const AWS = "AKIARECOVEREDSOURCE1";'''
vendor_src = '''/*! jQuery JavaScript Library v1.12.4 */
fetch("/api/vendor-noise-endpoint");
const k = "AKIAVENDORNOISEXXXX1";'''
smap = json.dumps({"version": 3, "names": [], "mappings": "AAAA",
    "sources": ["webpack:///./src/api.ts", "webpack:///./node_modules/jquery/dist/jquery.js"],
    "sourcesContent": [app_src, vendor_src]})

routes = {
    "/": '<html><script>var cfg = {u: "/api/from-inline"};</script><script src="/app.js"></script></html>',
    "/app.js": "var x=1;\n//# sourceMappingURL=app.js.map",
    "/app.js.map": smap,
}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = routes.get(self.path)
        self.send_response(200 if body is not None else 404); self.end_headers()
        if body is not None: self.wfile.write(body.encode())

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

cli.lookup_cves = lambda libs, **kw: []   # no network calls to OSV in tests
sys.argv = ["jxray", f"http://127.0.0.1:{srv.server_port}/",
            "--endpoints", "--params", "--secrets", "--cve", "--report",
            "--retire", "--semgrep", "--linkfinder", "--output-dir", str(OUT)]
cli.main()

fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

def log(name):
    f = LOGS / name
    return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []

ext, inl, smr = (str(OUT / d) for d in ("external", "inline", "sourcemap_recovered"))

# regex analyses
endpoints = (OUT / "endpoints.txt").read_text().splitlines()
check(any("recovered-users" in e for e in endpoints), "endpoints: include first-party recovered source")
check(not any("vendor-noise" in e for e in endpoints), "endpoints: exclude node_modules noise")
check("tenantId" in (OUT / "params_wordlist.txt").read_text(), "params: include recovered source")
report = (OUT / "report.html").read_text()
secret_vals = {s["value"] for s in json.loads((OUT / "secrets.json").read_text())}
check("AKIARECOVEREDSOURCE1" in secret_vals, "secrets: AWS key from recovered source found")
check("AKIAVENDORNOISEXXXX1" not in secret_vals, "secrets: vendor-only key not reported")
check("jquery" in report and "1.12.4" in report, "CVE fingerprint: jquery version seen in recovered node_modules")

# external tools
retire_paths = [a[a.index("--path") + 1] for a in log("retire")]
check(sorted(retire_paths) == sorted([ext, inl, smr]), f"retire scans external+inline+sourcemap_recovered ({retire_paths})")
sg = log("semgrep")
check(len(sg) == 1 and all(d in sg[0] for d in (ext, inl, smr)), "semgrep gets all three dirs in one run")
check(len(sg) == 1 and all(v in sg[0] for v in ("node_modules", "bower_components")) and "--exclude" in sg[0],
      "semgrep excludes vendor dirs")
lf_files = [a[a.index("-i") + 1] for a in log("linkfinder")]
check(any(f.endswith("api.ts") for f in lf_files), "LinkFinder scans recovered .ts source")
check(any("/inline/" in f for f in lf_files), "LinkFinder scans inline blocks")
check(not any("node_modules" in f for f in lf_files), "LinkFinder skips node_modules")

# unit
root = Path("/x/out/sourcemap_recovered")
check(not cli.is_vendor_path(Path("/node_modules/x/out/sourcemap_recovered/b/src/a.js"), Path("/node_modules/x/out/sourcemap_recovered")),
      "is_vendor_path: ignores vendor names above the root")
check(cli.is_vendor_path(root / "b/webpack_/node_modules/react/index.js", root), "is_vendor_path: detects node_modules")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
