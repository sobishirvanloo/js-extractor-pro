"""CVE/CVSS scoring + filename-based version detection; the beautify size cap;
--input-dir local analysis (no network); and batch/target-selection helpers.

Usage: python tests/suite_versions_local.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import json, sys, tempfile
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(Path(_REPO).resolve()))

from jxray import cli
from jxray.analyzers import versions
from jxray.output import beautify, light_prettify

TMP = Path(tempfile.mkdtemp(prefix="jsx-vtest-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

# ── CVSS v3.x base-score calculation (spec section 7.1 reference vectors) ─────
CVSS = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "CRITICAL"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": (6.1, "MEDIUM"),
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N": (1.8, "LOW"),
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": (5.9, "MEDIUM"),
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "CRITICAL"),
}
for vec, (score, label) in CVSS.items():
    got = versions.cvss3_base_score(vec)
    check(got == score, f"CVSS {vec.split('/',1)[1][:18]}… -> {got} (expect {score})")
    check(versions.severity_label(got) == label, f"  band {got} -> {versions.severity_label(got)} (expect {label})")

check(versions.cvss3_base_score("CVSS:4.0/AV:N") is None, "v4 vector -> None (not scored as v3)")
check(versions.cvss3_base_score("not a vector") is None, "garbage vector -> None")
check(versions.severity_label(None) == "", "no score -> empty band")
check(versions.severity_label(0.0) == "NONE", "score 0 -> NONE")

# ── version fingerprinting from body banners AND versioned filenames ─────────
banner = versions.detect_library_versions("/*! jQuery JavaScript Library v3.4.1 */ var x=1;")
check(banner == [{"name": "jquery", "version": "3.4.1"}], f"banner -> jquery 3.4.1 ({banner})")

from_urls = versions.detect_library_versions("", urls=[
    "https://cdn/static/jquery-3.5.1.min.js",   # versioned filename
    "https://cdn/vue@2.6.14/dist/vue.js",        # @version
    "https://cdn/app.9fe2 bc.chunk.js".replace(" ", ""),  # hashed chunk -> no version
])
names = {(l["name"], l["version"]) for l in from_urls}
check(("jquery", "3.5.1") in names, f"URL jquery-3.5.1.min.js detected ({from_urls})")
check(("vue", "2.6.14") in names, "URL vue@2.6.14 detected")
check(all(n != "app" for n, _ in names), "hashed chunk filename yields no bogus version")

# ── lookup_cves: querybatch + per-vuln detail fetch, with network mocked ─────
class _Resp:
    def __init__(self, payload): self._p = payload
    def raise_for_status(self): pass
    def json(self): return self._p

_VULN = {
    "GHSA-aaaa-bbbb-cccc": {
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2020-11111"],
        "summary": "Prototype pollution in example lib",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    },
}
batch_calls, get_calls = [], []
def fake_post(url, json=None, timeout=None):
    batch_calls.append(url)
    # one query hit (jquery), one miss (lodash) — order matches input
    return _Resp({"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}, {}]})
def fake_get(url, timeout=None):
    get_calls.append(url)
    return _Resp(_VULN[url.rsplit("/", 1)[-1]])

versions.requests.post = fake_post
versions.requests.get = fake_get
versions.time.sleep = lambda *_: None

cves = versions.lookup_cves([{"name": "jquery", "version": "3.4.1"},
                             {"name": "lodash", "version": "4.17.10"}])
check(len(batch_calls) == 1 and batch_calls[0].endswith("/querybatch"),
      f"one batched querybatch call ({len(batch_calls)})")
check(len(cves) == 1, f"only the matching library yields a CVE ({len(cves)})")
if cves:
    c = cves[0]
    check(c["library"] == "jquery" and c["cve"] == "CVE-2020-11111", "CVE aliased + attributed to jquery")
    check(c["cvss_score"] == 9.8 and c["severity"] == "CRITICAL", f"numeric CVSS + band ({c['cvss_score']}, {c['severity']})")

check(versions.lookup_cves([]) == [], "empty library list -> no lookups")

# ── beautify size cap ────────────────────────────────────────────────────────
small = "var a=1;function f(){return 2;}"
check("\n\nfunction" in beautify(small, 2_000_000), "small file fully beautified")
big = small * 50_000
out = beautify(big, 100_000)
check(out.splitlines()[0].startswith("/* note: file exceeded beautify size cap"),
      "oversized file gets the light-prettify note")
check(out.count("\n") > 1000, "light prettify still splits into many lines")
check("\n\nfunction" in beautify(big, 0), "max_bytes=0 forces full beautify even when large")

# ── target-selection helpers ─────────────────────────────────────────────────
check(cli._is_http_url("https://a.com/x") and not cli._is_http_url("ftp://a")
      and not cli._is_http_url("nope"), "_is_http_url accepts only http(s) with a host")
check(cli._safe_target_dir("https://e.com/a") != cli._safe_target_dir("https://e.com/b"),
      "same host, different path -> distinct output dirs")

lst = TMP / "targets.txt"
lst.write_text("# comment\nhttps://a.com\n\nhttps://b.com\nhttps://a.com\n")
class _P:   # minimal stand-in for argparse parser.error
    def error(self, m): raise SystemExit(m)
got = cli._read_target_list(str(lst), _P())
check(got == ["https://a.com", "https://b.com"], f"list parsed: comments/blanks/dupes dropped ({got})")

# ── --input-dir end to end (no network) ──────────────────────────────────────
indir = TMP / "src"
(indir / "sub").mkdir(parents=True)
# Build the token in Python so no contiguous AKIA… literal sits in this test
# file (GitHub push protection would flag it), but the written JS gets one.
_awskey = "AKIA" + "IOSFODNN7QWERTZU"
(indir / "app.min.js").write_text(
    'var u="/api/v1/users";fetch("/api/internal/admin",{method:"POST"});'
    'var k="' + _awskey + '";el.innerHTML=location.hash;')
(indir / "sub" / "x.js").write_text('$.ajax({url:"/search",type:"GET"});')
outdir = TMP / "out"
sys.argv = ["jsx", "--input-dir", str(indir), "--output-dir", str(outdir),
            "--endpoints", "--params", "--secrets", "--dom"]
code = 0
try:
    cli.main()
except SystemExit as e:
    code = e.code or 0
check(code == 0, f"--input-dir run exited 0 ({code})")

res = json.loads((outdir / "results.json").read_text())
check(res["target"].startswith("local:"), "target marked local:")
check(res["scope"]["allowed"] == "local files (no network)", "scope describes local mode")
check(len(res["files"]) == 2 and all(f["kind"] == "local" for f in res["files"]),
      f"both local files recorded as kind=local ({[f['kind'] for f in res['files']]})")
check("/api/internal/admin" in res["hidden_endpoints"], "hidden endpoint found in local file")
check("/search" in res["endpoints"], "endpoint from nested file found")
sev_types = {(s["type"], s["severity"]) for s in res["secrets"]}
check(("AWS Access Key ID", "high") in sev_types, f"AWS key found in local file ({sev_types})")
check(any(d["sink"] == "innerHTML" and d["severity"] == "high" for d in res["dom_findings"]),
      "innerHTML<-location.hash DOM flow found in local file")
check(all(f["saved_path"].startswith("local/") for f in res["files"]),
      "beautified copies written under local/")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
