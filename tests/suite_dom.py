"""DOM XSS analysis (--dom): sinks, sources, source→sink flow (direct, via a
tainted variable, postMessage data), constant-argument filtering, false-positive
guards, file:line accuracy, grouping across bundle + recovered source, report
escaping, --fail-on dom, and linear time on hostile input.

Usage: python tests/suite_dom.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import contextlib, io, json, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(Path(_REPO).resolve()))
from js_extractor import cli

TMP = Path(tempfile.mkdtemp(prefix="jsx-test-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

# ── unit: classification ─────────────────────────────────────────────────────
SAMPLE = r'''
el.innerHTML = location.hash.slice(1);
el.innerHTML = "";
el.innerHTML = "<b>" + 'x' + "</b>";
if (el.innerHTML == "x") {}
var q = new URLSearchParams(location.search).get("q");
var unused = 1;
box.innerHTML = q;
eval(userInput);
eval("1+1");
setTimeout("go(" + id + ")", 10);
setTimeout(fn, 10);
window.addEventListener("message", function(e) {
  document.getElementById("x").innerHTML = e.data;
});
window.addEventListener("message", (ev) => {
  if (ev.origin !== "https://trusted.example") return;
  out.innerHTML = ev.data;
});
window.onmessage = function(ev) { eval(ev.data) };
target.postMessage(token, "*");
target.postMessage(token, "https://ok.example");
location.href = new URLSearchParams(location.search).get("next");
this.sanitizer.bypassSecurityTrustHtml(html);
React.createElement("div", { dangerouslySetInnerHTML: { __html: props.bio } });
xhr.open("GET", url);
fd.append("a", b);
$("#x").html(location.hash);
document.write("<script src=" + document.referrer + ">");
el.insertAdjacentHTML("beforeend", window.name);
foo.location = bar;
var qq = 5; other.innerHTML = qqq;
'''
F = cli.find_dom_issues(SAMPLE)
by_line = {}
for f in F:
    by_line.setdefault(f["line"], []).append(f)

def at(line, sink=None):
    return [f for f in by_line.get(line, []) if sink is None or f["sink"] == sink]

def sev(line, sink=None):
    hits = at(line, sink)
    return hits[0]["severity"] if hits else None

check(sev(2) == "high" and at(2)[0]["flow"] == "direct", "innerHTML = location.hash → high, direct")
check(not at(3) and not at(4), "constant innerHTML values ('' and literal concat) skipped")
check(not at(5), "innerHTML comparison (==) is not a sink")
check(sev(8) == "high" and at(8)[0]["flow"] == "via variable 'q'", "source → variable → innerHTML → high, via variable")
check(sev(9) == "medium" and at(9)[0]["flow"] is None, "eval(non-literal) without source → medium")
check(not at(10), "eval(constant) skipped")
check(sev(11) == "medium" and not at(12), "setTimeout(string concat) flagged; setTimeout(fn) not")
check(sev(13, "message handler without origin check") == "high", "message handler without origin check → high")
check(sev(14) == "high" and at(14)[0]["flow"] == "message data", "e.data → innerHTML inside unchecked handler → high")
check(not at(16, "message handler without origin check") and sev(18) == "low",
      "handler WITH origin check: not reported; its sink stays low")
check(sev(20, "eval") == "high", "onmessage = function(ev){ eval(ev.data) } → high")
check(sev(21) == "medium" and not at(22), 'postMessage(…, "*") flagged; explicit target origin not')
check(sev(23) == "high", "location.href = <URL param> → high (open redirect / javascript: XSS)")
check(sev(24) == "medium", "Angular bypassSecurityTrustHtml → medium")
check(sev(25) == "low", "dangerouslySetInnerHTML with non-source prop → low")
check(not at(26) and not at(27), "XMLHttpRequest.open and FormData.append are not sinks")
check(sev(28) == "high" and sev(29) == "high" and sev(30) == "high",
      "jQuery .html(location.hash), document.write(referrer), insertAdjacentHTML(window.name) → high")
check(not at(31), "foo.location = … (other object's property) is not navigation")
check(sev(32) == "low", "variable qq does not taint qqq (word boundary)")
check([f["severity"] for f in F] == sorted([f["severity"] for f in F], key=["high", "medium", "low"].index),
      "findings sorted by severity")

# ── unit: linear time on hostile input ───────────────────────────────────────
N = 600_000
hostile = {
    "long word": "var big='" + "x" * N + "';",
    "minified line": "a.innerHTML=b+c;var q=location.hash;eval(q);" * (N // 45),
    "unterminated": "x.innerHTML=" + "(" * (N // 2),
    "msg handlers": 'addEventListener("message",function(e){' * (N // 40),
}
for name, s in hostile.items():
    t0 = time.time(); r = cli.find_dom_issues(s); dt = time.time() - t0
    check(dt < 5 and all(len(f["snippet"]) <= 250 for f in r), f"hostile input '{name}': {dt:.2f}s, snippets bounded")

# ── integration: bundle + inline + recovered source ──────────────────────────
BUNDLE = ('function render(){\n  var t = location.hash.substr(1);\n  document.getElementById("o").innerHTML = t;\n}\n'
          'var payload = "x"; el.innerHTML = "<img src=x onerror=alert(1)>" + location.hash;\n'
          '//# sourceMappingURL=app.js.map')
ORIGINAL = ('export function render() {\n  const t = location.hash.substr(1);\n'
            '  document.getElementById("o").innerHTML = t;\n}\n')
routes = {
    "/": ('<html><script>window.addEventListener("message", function (e) { eval(e.data); });</script>'
          '<script src="/app.js"></script></html>'),
    "/app.js": BUNDLE,
    "/app.js.map": json.dumps({"version": 3, "names": [], "mappings": "AAAA",
                               "sources": ["webpack:///./src/render.js"], "sourcesContent": [ORIGINAL]}),
}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        b = routes.get(self.path)
        self.send_response(200 if b is not None else 404); self.end_headers()
        if b is not None: self.wfile.write(b.encode())
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_port}/"

def run_main(argv):
    sys.argv = ["js-extractor"] + argv
    buf = io.StringIO(); code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, buf.getvalue()

OUT = TMP / "o1"
code, out = run_main([BASE, "--dom", "--report", "--rate-limit", "0", "--output-dir", str(OUT)])
check(code == 0, "run with --dom succeeds")
dom = json.loads((OUT / "dom_sinks.json").read_text())
res = json.loads((OUT / "results.json").read_text())
check(res["dom_findings"] == dom, "results.json carries the same dom_findings as dom_sinks.json")

def on_disk(loc):
    return (OUT / loc["file"]).read_text().splitlines()[loc["line"] - 1]

check(dom and all(any(tok in on_disk(l) for tok in ("innerHTML", "message", "eval"))
                  for d in dom for l in d["locations"]), "every file:line points at the sink on disk")
render = [d for d in dom if d["sink"] == "innerHTML" and d["flow"] == "via variable 't'"]
files = {l["file"].split("/")[0] for d in render for l in d["locations"]}
check(render and {"external", "sourcemap_recovered"} <= files,
      "same sink in bundle + recovered source found in both (high, via variable)")
check(any(d["sink"] == "message handler without origin check" and d["file"].startswith("inline/") for d in dom),
      "message handler in an inline <script> found")
check("[high]" in out and "dom_sinks.json" in out, "terminal summary shows high findings")

report = (OUT / "report.html").read_text()
check("DOM XSS Sinks" in report and "<img src=x onerror" not in report and "&lt;img src=x onerror" in report,
      "report: DOM section present, attacker-shaped snippet escaped")

code, out = run_main([BASE, "--fail-on", "dom", "--rate-limit", "0", "--output-dir", str(TMP / "o2")])
check(code == 3 and "--fail-on matched: dom" in out, "--fail-on dom → exit 3 (and implies --dom)")
code, _ = run_main([BASE, "--rate-limit", "0", "--output-dir", str(TMP / "o3")])
r3 = json.loads((TMP / "o3" / "results.json").read_text())
check(r3["dom_findings"] == [] and not (TMP / "o3" / "dom_sinks.json").exists(), "without --dom: no DOM analysis")
cli.lookup_cves = lambda libs, **kw: []          # no network in --all-analysis
code, _ = run_main([BASE, "--all-analysis", "--rate-limit", "0", "--output-dir", str(TMP / "o4")])
check((TMP / "o4" / "dom_sinks.json").exists(), "--all-analysis includes --dom")


# ── taint engine: sources, multi-hop, calls, sanitizers, prefixes, handlers ──
TAINT_JS = (Path(__file__).resolve().parent / "fixtures_dom_taint.js").read_text()
T = {}
for f in cli.find_dom_issues(TAINT_JS):
    T.setdefault(f["line"], []).append(f)

def tf(line, sink=None):
    hits = [f for f in T.get(line, []) if sink is None or sink in f["sink"]]
    return hits[0] if hits else None

def expect(line, severity, msg, sink=None, flow=None, trace_has=None, kind=None):
    f = tf(line, sink)
    ok = f is not None and f["severity"] == severity
    if ok and flow is not None:
        ok = (f["flow"] or "").startswith(flow)
    if ok and trace_has is not None:
        ok = all(t in f.get("trace_text", "") for t in trace_has)
    if ok and kind is not None:
        ok = f["kind"] == kind
    check(ok, f"L{line}: {msg} ({f and (f['severity'], f['flow'], f.get('trace_text', '')[:80])})")

expect(2, "high", "Vue $route.query → innerHTML", trace_has=["Vue $route"])
expect(4, "high", "useSearchParams() → sp → term → innerHTML (2 hops)", flow="via variable 'term'",
       trace_has=["useSearchParams()", "sp (L4)", "term (L4)"])
expect(6, "high", "Next router.query → location", trace_has=["router.query"])
expect(8, "high", "Angular ActivatedRoute → location", trace_has=["Angular ActivatedRoute"])
expect(13, "high", "3-hop chain a1 → b1 → c1 → innerHTML", trace_has=["a1 (L10)", "b1 (L11)", "c1 (L12)", "innerHTML (L13)"])
expect(17, "low", "clean reassignment kills the taint")
expect(19, "high", "function param sink called with location.search", flow="via call renderHtml()",
       trace_has=["location (L20)", "renderHtml() arg 1 (L20)", "html (L19)"])
expect(22, "high", "arrow fn param sink called with tainted variable", flow="via call showMsg()",
       trace_has=["msg (L23)", "m (L22)"])
check(tf(25) and tf(25)["sanitized"] and tf(25)["severity"] == "low", "DOMPurify.sanitize(source) → low, sanitized")
check(tf(26) and tf(26)["sanitized"] and tf(26)["severity"] == "low", "sanitized value stays sanitized through a variable")
expect(28, "low", "constant same-origin path prefix → low")
expect(29, "medium", '"//" + source → open redirect, medium')
expect(30, "high", "source as the whole URL → high")
expect(32, "high", "createElement('script').src = source", kind="script-url")
expect(33, "high", "createElement('iframe').src = referrer", kind="nav")
expect(34, "medium", "createElement('a').href = source (needs a click)", kind="nav-click")
expect(36, "high", "$(location.hash)", sink="jQuery $(")
expect(37, "high", "$(…).append(location.hash)", sink="jQuery DOM insertion")
check(tf(38) is None, "$('.btn') with a constant selector is not reported")
expect(40, "medium", "weak origin check (indexOf) → handler medium", sink="weak origin check")
expect(40, "medium", "eval(e.data) under a weak origin check → medium", sink="eval")
check(not [f for f in T.get(41, []) if "origin" in f["sink"]] and tf(41)["severity"] == "low",
      "strict origin check: no handler finding, its sink low")
expect(42, "high", "named handler (onMsg) resolved: evt.data → innerHTML", flow="message data")
expect(43, "high", "named handler registration without origin check", sink="without origin check")
expect(44, "high", "destructured ({data}) handler → innerHTML", sink="innerHTML", flow="message data")
expect(46, "medium", "localStorage.getItem → innerHTML: stored source, medium")
expect(47, "medium", "localStorage.setItem(source)", kind="storage-write")
expect(48, "medium", "document.cookie = … + source", kind="cookie-write")
expect(50, "high", "new Worker(source)", kind="script-url")
expect(51, "high", "import(source)", kind="script-url")
check(tf(52) is None, "import() with a constant or untainted argument is not reported")
expect(54, "high", "tainted variable passed to setTimeout", flow="via variable 'code1'")
expect(56, "low", "Angular [innerHTML] binding: low (framework-sanitized)", kind="html-sanitized")
inv = cli.find_dom_sources(TAINT_JS)
cats = {s["category"] for s in inv}
check({"url", "framework-route", "referrer", "storage"} <= cats and all(s["line"] >= 1 for s in inv),
      f"source inventory covers url/framework-route/referrer/storage ({sorted(cats)})")

# minified name reuse: a short tainted name must not reach a far-away sink
far = "e=location.hash;" + ";x=1" * 600 + ";y.innerHTML=e;"
check(cli.find_dom_issues(far)[0]["severity"] == "low", "short (minified) name: taint expires with distance")

# results.json + report carry the new fields
check(res.get("dom_sources") and (OUT / "dom_sources.json").exists(), "dom_sources.json + results.json dom_sources")
check(all("confidence" in d for d in dom), "every finding has a confidence")
check("→" in report and "confidence" in report, "report shows trace and confidence")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
