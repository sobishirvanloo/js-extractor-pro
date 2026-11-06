"""
GraphQL / config / replay / source-intel analyzers, plus their CLI wiring:
--input-dir end to end, the dependency-confusion --fail-on gate (npm mocked),
and the guarantee that --all-analysis fires no active-network extras.

Usage: python tests/suite_recon_features.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import json, sys, tempfile
from pathlib import Path

_REPO = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(Path(_REPO).resolve()))

from js_extractor import cli
from js_extractor.analyzers.graphql import find_graphql_in_files, parse_introspection
from js_extractor.analyzers.config import find_config_in_files
from js_extractor.analyzers.replay import build_openapi, build_curl_commands, build_ffuf_commands
from js_extractor.analyzers.sourceintel import find_source_intel, check_npm_packages

TMP = Path(tempfile.mkdtemp(prefix="jsx-recon-"))
atexit.register(shutil.rmtree, TMP, True)
fails = []
def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

# ── GraphQL extraction ───────────────────────────────────────────────────────
GQL_JS = r'''
const A = gql`query GetUser($id: ID!){ user(id:$id){ id name } flags }`;
fetch("/api/graphql",{method:"POST",body:JSON.stringify({query:"mutation Del{ deleteUser{ ok } }"})});
const link = new HttpLink({ uri: "https://api.x.com/graphql" });
fragment UP on User { id }
'''
g = find_graphql_in_files([("app.js", GQL_JS, 0)])
ops = {(o["type"], o["name"]): o for o in g["operations"]}
check(("query", "GetUser") in ops and ("mutation", "Del") in ops, f"query+mutation extracted ({list(ops)})")
check("user" in ops[("query", "GetUser")]["fields"] and "flags" in ops[("query", "GetUser")]["fields"],
      "root fields of GetUser captured")
check({e["url"] for e in g["endpoints"]} == {"/api/graphql", "https://api.x.com/graphql"},
      f"both endpoints found ({[e['url'] for e in g['endpoints']]})")
check(any(f["name"] == "UP" and f["on"] == "User" for f in g["fragments"]), "fragment captured")

intro = parse_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "subscriptionType": None, "types": [{"name": "User", "kind": "OBJECT"}, {"name": "__Type", "kind": "OBJECT"}]}}})
check(intro and intro["query_type"] == "Query" and intro["type_count"] == 1 and intro["types"] == ["User"],
      f"introspection parsed, __types filtered ({intro})")
check(parse_introspection({"errors": [{"message": "nope"}]}) is None, "non-schema introspection -> None")

# ── config extraction ────────────────────────────────────────────────────────
CFG_JS = r'''
window.__CONFIG__ = { api:"https://api.internal.corp", tenant:"acme" };
const flags = { enableBeta:true, showDebug:false };
fetch("http://10.1.2.3:9000/x");
img.src="https://b.s3.amazonaws.com/o";
const k = process.env.SECRET_TOKEN;
'''
cfg = find_config_in_files([("app.js", CFG_JS, 0)])
kinds = {c["kind"] for c in cfg}
check({"config-object", "feature-flag", "internal-host", "cloud-resource", "env-var"} <= kinds,
      f"all config kinds detected ({sorted(kinds)})")
check(any(c["kind"] == "feature-flag" and c["name"] == "enableBeta" and c["value"] == "true" for c in cfg),
      "boolean feature flag captured with value")
check(any(c["kind"] == "internal-host" and "10.1.2.3" in c["value"] for c in cfg), "internal IP captured")

# ── replay builders ──────────────────────────────────────────────────────────
EPS = [
    {"path": "/api/users", "methods": ["GET", "POST"], "hidden": False, "file": "a.js", "line": 1},
    {"path": "/admin/debug", "methods": ["DELETE"], "hidden": True, "file": "a.js", "line": 2},
    {"path": "/u/{param}", "methods": ["GET"], "hidden": False, "file": "a.js", "line": 3},
]
doc = build_openapi(EPS, ["q", "page"], "https://t.example.com/app")
check(doc["openapi"].startswith("3.0") and set(doc["paths"]) == {"/api/users", "/admin/debug", "/u/{param}"},
      "openapi paths built")
check(doc["paths"]["/u/{param}"]["get"]["parameters"][0]["name"] == "param", "path param modelled")
check(doc["paths"]["/admin/debug"]["delete"].get("x-hidden") is True, "hidden endpoint flagged in openapi")
check(doc["x-discovered-params"] == ["page", "q"], "discovered params preserved")
curls = build_curl_commands(EPS, "https://t.example.com/app", {"Authorization": "Bearer T"}, "s=1")
check(any("-X POST" in c and "Authorization: Bearer T" in c for c in curls), "curl carries method + auth")
check(any("# hidden" in c for c in curls), "hidden endpoint tagged in curl output")
ffufs = build_ffuf_commands(EPS, "https://t.example.com/app")
check(ffufs and "FUZZ" in ffufs[0] and "{param}" not in " ".join(ffufs), "ffuf lines built, templated paths skipped")
check(build_openapi(EPS, [], "local:/tmp/x")["servers"][0]["url"] == "https://TARGET",
      "local target -> placeholder server")

# ── source intel + dependency-confusion (npm mocked) ─────────────────────────
SI_JS = "import x from '@acme/private-kit';\nimport React from 'react';\n// FIXME: remove test backdoor\n"
si = find_source_intel([("a.js", SI_JS, 0)], ["webpack:///./src/app.ts", "webpack:///node_modules/react/i.js"])
check("@acme/private-kit" in si["packages"] and "react" in si["packages"], "packages from import + node_modules path")
check("src/app.ts" in si["tree"], "first-party tree path recovered")
check(any(t["tag"] == "FIXME" for t in si["todos"]), "FIXME comment captured")

class _Resp:
    def __init__(self, code): self.status_code = code
calls = []
def fake_get(url, timeout=None):
    calls.append(url)
    return _Resp(404 if "private-kit" in url else 200)   # scoped internal pkg is unpublished
import js_extractor.analyzers.sourceintel as _si_mod
_si_mod.requests.get = fake_get
_si_mod.time.sleep = lambda *_: None
dep = check_npm_packages(["@acme/private-kit", "react"])
claim = [d for d in dep if d["status"] == "claimable"]
check(len(claim) == 1 and claim[0]["name"] == "@acme/private-kit" and claim[0]["risk"] == "high",
      f"scoped unpublished pkg flagged claimable/high ({dep})")
check(any(d["name"] == "react" and d["status"] == "public" for d in dep), "published pkg -> public")

# ── CLI: --input-dir end to end with all static new analyzers ────────────────
indir = TMP / "src"
indir.mkdir()
(indir / "app.js").write_text(GQL_JS + CFG_JS + SI_JS + 'fetch("/api/v1/items",{method:"GET"});')
out = TMP / "out"
# npm + OSV mocked so the batch dep-confusion run makes no real network calls
cli.check_npm_packages = lambda names, **kw: [
    {"name": n, "scoped": n.startswith("@"),
     "status": ("claimable" if n.startswith("@") else "public"),
     "risk": ("high" if n.startswith("@") else "none")} for n in names]
cli.lookup_cves = lambda libs, **kw: []

sys.argv = ["jsx", "--input-dir", str(indir), "--output-dir", str(out),
            "--endpoints", "--params", "--graphql", "--config", "--source-intel",
            "--replay", "--dep-confusion", "--fail-on", "dep-confusion"]
code = 0
try:
    cli.main()
except SystemExit as e:
    code = e.code or 0
check(code == 3, f"--fail-on dep-confusion gate trips on claimable pkg (exit {code})")

res = json.loads((out / "results.json").read_text())
check(len(res["graphql"]["operations"]) >= 2, "results.json carries graphql operations")
check(any(c["kind"] == "internal-host" for c in res["config"]), "results.json carries config")
check(res["source_intel"]["packages"], "results.json carries source_intel packages")
check(any(d["status"] == "claimable" for d in res["dep_confusion"]), "results.json carries dep_confusion")
check(res["replay"]["openapi_paths"] >= 1, "results.json carries replay summary")
for fn in ("graphql.json", "config.json", "source_intel.json", "dep_confusion.json",
           "openapi.json", "curl_commands.sh", "ffuf_commands.sh"):
    check((out / fn).is_file(), f"artefact written: {fn}")

# ── CLI: --all-analysis must NOT fire active-network extras ───────────────────
def _boom(*a, **k):
    raise AssertionError("check_npm_packages must not be called under --all-analysis")
cli.check_npm_packages = _boom
out2 = TMP / "out2"
sys.argv = ["jsx", "--input-dir", str(indir), "--output-dir", str(out2), "--all-analysis"]
code2 = 0
try:
    cli.main()
except SystemExit as e:
    code2 = e.code or 0
except AssertionError as e:
    check(False, str(e))
    code2 = -1
check(code2 in (0, 3), f"--all-analysis completes without active npm lookups (exit {code2})")
if (out2 / "results.json").is_file():
    r2 = json.loads((out2 / "results.json").read_text())
    check(r2["dep_confusion"] == [], "--all-analysis leaves dep_confusion empty (opt-in only)")
    check(r2["graphql"]["operations"], "--all-analysis still runs static GraphQL extraction")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
