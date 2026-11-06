"""Performance & output: --threads, --rate-limit, --max-files, --max-size, soft-404 skip,
results.json / --json, --fail-on.

Usage: python tests/suite_performance_output.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import contextlib, io, json, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
REPO = Path(_REPO).resolve()
sys.path.insert(0, str(REPO))
from jxray import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

N = 10
DELAY = 0.5
state = {"inflight": 0, "max_inflight": 0, "times": []}
lock = threading.Lock()

def page(secret=False):
    tags = "".join(f'<script src="/s{i}.js"></script>' for i in range(N))
    tags += '<script src="/missing.js"></script><script src="/big.js"></script><script src="/big-chunked.js"></script>'
    tags += '<script src="/app.js"></script><script src="/needs-cookie.js"></script>'
    if secret:
        tags += '<script>var k = "AKIASTAGETHREETEST01";</script>'
    return f"<html>{tags}</html>"

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a): pass
    def send(self, code, body, headers=None, length=True):
        self.send_response(code)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        if length: self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        with lock:
            state["times"].append(time.monotonic())
        p = self.path
        if p in ("/", "/secret"):
            return self.send(200, page(p == "/secret").encode(), {"Set-Cookie": "waf=ok; Path=/"})
        if p.startswith("/s") and p.endswith(".js"):
            with lock:
                state["inflight"] += 1
                state["max_inflight"] = max(state["max_inflight"], state["inflight"])
            time.sleep(DELAY)
            with lock:
                state["inflight"] -= 1
            return self.send(200, f"var v{p[2:-3]} = '/api/v1/item{p[2:-3]}';".encode())
        if p == "/missing.js":
            return self.send(200, b"<!DOCTYPE html><html><body>Not found</body></html>")
        if p == "/big.js":
            return self.send(200, b"var big='" + b"x" * (2 * 1048576) + b"';")
        if p == "/big-chunked.js":   # no Content-Length → must be caught while streaming
            return self.send(200, b"var big2='" + b"y" * (2 * 1048576) + b"';", length=False)
        if p == "/app.js":
            return self.send(200, b"import('./chunk.js');")
        if p == "/chunk.js":
            return self.send(200, b"var chunk = '/api/v1/chunk';")
        if p == "/needs-cookie.js":
            ok = "waf=ok" in self.headers.get("Cookie", "")
            return self.send(200 if ok else 403, b"var waf=1;" if ok else b"forbidden")
        self.send(404, b"")

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_port}"

def run_main(argv):
    sys.argv = ["jxray"] + argv
    buf = io.StringIO(); code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, buf.getvalue()

def reset():
    state.update(inflight=0, max_inflight=0, times=[])

# ── parallelism + correctness ────────────────────────────────────────────────
reset()
t0 = time.monotonic()
code, out = run_main([BASE + "/", "--threads", "5", "--rate-limit", "0", "--max-size", "1",
                      "--endpoints", "--output-dir", str(TMP / "p1")])
elapsed = time.monotonic() - t0
check(code == 0, "parallel run succeeds")
check(state["max_inflight"] >= 4, f"threads: up to {state['max_inflight']} downloads in flight at once")
check(elapsed < N * DELAY * 0.6, f"threads: {N} x {DELAY}s scripts took {elapsed:.1f}s (serial would be ≥{N*DELAY:.0f}s)")
res = json.loads((TMP / "p1" / "results.json").read_text())
names = sorted(f["saved_path"] for f in res["files"] if f["kind"] == "external")
check(any("chunk.js" in n for n in names), "imports discovered by workers are fetched in the next wave")
check(any("needs-cookie" in n for n in names), "cookie set by target on page load reaches worker threads")
check(any(u.endswith("/missing.js") for u in res["skipped"]["not_javascript"])
      and not any("missing" in n for n in names), "soft-404 HTML page skipped, not saved as JS")
check({u.rsplit("/", 1)[1] for u in res["skipped"]["too_large"]} == {"big.js", "big-chunked.js"},
      "--max-size: oversized responses skipped (with and without Content-Length)")
check("/api/v1/item3" in res["endpoints"] and "/api/v1/chunk" in res["endpoints"], "endpoints from parallel downloads")

# determinism: same numbering & order on a second run
code, _ = run_main([BASE + "/", "--threads", "5", "--rate-limit", "0", "--max-size", "1",
                    "--endpoints", "--output-dir", str(TMP / "p2")])
res2 = json.loads((TMP / "p2" / "results.json").read_text())
check([f["saved_path"] for f in res["files"]] == [f["saved_path"] for f in res2["files"]]
      and res["endpoints"] == res2["endpoints"], "output is deterministic across runs despite threading")
first = [f for f in res["files"] if f["kind"] == "external"][0]
check(first["saved_path"].startswith("external/ext_001_") and first["url"].endswith("/s0.js"),
      "file numbering follows discovery order")

# ── rate limit ───────────────────────────────────────────────────────────────
reset()
t0 = time.monotonic()
run_main([BASE + "/", "--threads", "8", "--rate-limit", "4", "--max-files", "8", "--no-sourcemaps",
          "--output-dir", str(TMP / "r1")])
ts = sorted(state["times"])
span = ts[-1] - ts[0]
rate = (len(ts) - 1) / span if span else float("inf")
check(rate <= 4 * 1.15, f"--rate-limit 4: observed {rate:.2f} req/s over {len(ts)} requests")

# ── max-files ────────────────────────────────────────────────────────────────
code, _ = run_main([BASE + "/", "--max-files", "3", "--rate-limit", "0", "--no-sourcemaps",
                    "--output-dir", str(TMP / "m1")])
r = json.loads((TMP / "m1" / "results.json").read_text())
check(r["stats"]["external_downloaded"] == 3 and len(r["skipped"]["max_files"]) == N + 5 - 3,
      f"--max-files 3: 3 downloaded, {len(r['skipped']['max_files'])} skipped")

# ── --json on real stdout (subprocess) ───────────────────────────────────────
p = subprocess.run([sys.executable, "-I", str(REPO / "jxray" / "cli.py"), BASE + "/secret",
                    "--json", "--secrets", "--rate-limit", "0", "--no-sourcemaps",
                    "--output-dir", str(TMP / "j1")], capture_output=True, text=True, timeout=120)
try:
    doc = json.loads(p.stdout); ok = True
except json.JSONDecodeError:
    doc, ok = {}, False
check(p.returncode == 0 and ok, "--json: stdout is exactly one valid JSON document")
check("[DL]" in p.stderr and "[DL]" not in p.stdout, "--json: progress output goes to stderr")
check(doc.get("secrets") and doc["secrets"][0]["value"] == "AKIASTAGETHREETEST01"
      and doc["stats"]["findings"]["secrets"] == 1, "--json: findings + stats present")
check(json.loads((TMP / "j1" / "results.json").read_text()) == doc, "--json output == results.json")

p = subprocess.run([sys.executable, "-I", str(REPO / "jxray" / "cli.py"), "http://127.0.0.1:1/",
                    "--json", "--output-dir", str(TMP / "j2")], capture_output=True, text=True, timeout=120)
check(p.returncode == 1 and "error" in json.loads(p.stdout or "{}"), "--json: unreachable target → JSON error doc, exit 1")

# ── --fail-on ────────────────────────────────────────────────────────────────
code, out = run_main([BASE + "/secret", "--fail-on", "secrets", "--rate-limit", "0", "--no-sourcemaps",
                      "--output-dir", str(TMP / "f1")])
check(code == 3 and "--fail-on matched: secrets (1)" in out, "--fail-on secrets: exit 3 (and implies --secrets)")
code, _ = run_main([BASE + "/", "--fail-on", "secrets,hidden-endpoints", "--rate-limit", "0",
                    "--no-sourcemaps", "--output-dir", str(TMP / "f2")])
check(code == 0, "--fail-on: nothing found → exit 0")
code, out = run_main([BASE + "/", "--fail-on", "bogus"])
check(code == 2 and "unknown value" in out, "--fail-on: invalid value rejected")
code, out = run_main([BASE + "/", "--threads", "0"])
check(code == 2, "--threads 0 rejected")

# ── unit: RateLimiter ────────────────────────────────────────────────────────
rl = cli.RateLimiter(20); t0 = time.monotonic()
ths = [threading.Thread(target=rl.wait) for _ in range(11)]
[t.start() for t in ths]; [t.join() for t in ths]
check(0.45 <= time.monotonic() - t0 <= 1.0, "RateLimiter(20): 11 concurrent waits take ~0.5s")
t0 = time.monotonic(); [cli.RateLimiter(0).wait() for _ in range(1000)]
check(time.monotonic() - t0 < 0.1, "RateLimiter(0) is a no-op")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
