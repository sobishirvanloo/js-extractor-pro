"""Analysis accuracy: secret formats + severities + placeholder/entropy filtering
+ JWT role decoding; endpoints with HTTP method, file:line and token-based
"hidden" detection; request-only parameter extraction; --fail-on secrets
ignoring public-by-design keys; linear time on hostile input.

Usage: python tests/suite_accuracy.py   (or via pytest: tests/test_suites.py)
"""
import atexit, shutil
import base64, contextlib, io, json, sys, tempfile, threading, time
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

def jwt(payload):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'HS256', 'typ': 'JWT'})}.{b(payload)}.c2lnbmF0dXJlX3ZhbHVlXzk4NzY1"

# ── secrets: formats, severities, false-positive guards ──────────────────────
# Fake tokens are assembled at runtime from two pieces so no complete
# token-shaped string sits in the source: GitHub push protection (and other
# secret scanners) would otherwise flag this test file itself.
def T(*parts):
    return "".join(parts)

POSITIVE = {
    # label: (code template with {t}, fake token, expected severity)
    "AWS Access Key ID":      ('k = "{t}";', T("AKIA", "IOSFODNN7QWERTZU"), "high"),
    "Stripe Secret Key":      ('s = "{t}";', T("sk_li", "ve_51H8xYzQWEmnbVCXlkjHGF9"), "high"),
    "Stripe Publishable Key": ('Stripe("{t}")', T("pk_li", "ve_51H8xYzQWEmnbVCXlkjHGF9"), "low"),
    "SendGrid API Key":       ('"{t}"', T("SG.", "aB3dE5fG7hJ9kL1mN3pQ5r.sT7uV9wX1yZ3aB5cD7eF9gH1jK3lM5nP7qR9sT1uV3w"), "high"),
    "Slack Webhook":          ('"{t}"', T("https://hooks.slack", ".com/services/T0123ABCD/B0123ABCD/xyzXYZ0123456789qwrtQWRT"), "high"),
    "Discord Webhook":        ('"{t}"', T("https://discord.com/api/web", "hooks/123456789012/aB3-dE5_fG7hJ9"), "high"),
    "Mailgun API Key":        ('"{t}"', T("key-", "3ax6xnjp29jd6fds4gc373sgvjxteol0"), "high"),
    "Telegram Bot Token":     ('"{t}"', T("1234567890:", "AAH9xYzA1b2C3d4E5f6G7h8I9j0K1l2M3n4"), "high"),
    "npm Token":              ('"{t}"', T("npm_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"), "high"),
    "Credentials in URL":     ('"{t}:5432/app"', T("postgres://appuser:", "S3cr3t-P4ss@db.internal.corp.net"), "high"),
    "Google API Key":         ('"{t}"', T("AIza", "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"), "low"),
    "Sentry DSN":             ('"{t}"', T("https://0123456789abcdef0123456789abcdef", "@o12345.ingest.sentry.io/678"), "low"),
    "API Key":                ('{{"apiKey": "{t}"}}', T("f3a9c1e7b2d8", "4a6f9e0c5b7d1a3e8f20"), "medium"),
    "Password":               ('{{password: "{t}"}}', "hunter2x", "medium"),
}
for label, (template, value, sev) in POSITIVE.items():
    hits = [f for f in cli.find_secrets(template.format(t=value)) if f["value"] == value]
    check(len(hits) == 1 and hits[0]["type"] == label and hits[0]["severity"] == sev,
          f"secret {label}: found once, severity {sev} ({[(h['type'], h['severity']) for h in hits]})")

NEGATIVE = {
    "lowercase akia in base64":    'x = "aBcAkIaqwertyuiopasdfghjkl";',
    "sk- inside a word":           'task = "disk-qwertyuiopasdfghjklzxcvbnm";',
    "i18n key as password":        '{password: "auth.password"}',
    "autocomplete token":          '{password: "new-password"}',
    "env var name as secret":      '{secret: "CLIENT_SECRET_VALUE"}',
    "placeholder api key":         '{apiKey: "your-api-key-goes-here-123"}',
    "low-entropy api key":         '{apiKey: "aaaaaaaaaaaaaaaaaaaa"}',
    "identifier as api key":       '{apiKey: "googleMapsBrowserKeyName"}',
    "example.com credentials":     '"https://user:password@example.com/x"',
    "placeholder creds in URL":    '"mongodb://admin:<password>@cluster0.mongodb.net"',
}
for name, code in NEGATIVE.items():
    got = cli.find_secrets(code)
    check(not got, f"no false positive: {name} ({[(g['type'], g['value']) for g in got]})")

dup = cli.find_secrets('{"apiKey": "' + T("f3a9c1e7b2d8", "4a6f9e0c5b7d1a3e8f20") + '"}')
check(len(dup) == 1, "same value is reported once (API Key, not also Hex Secret)")

anon = cli.find_secrets(f'const k = "{jwt({"role": "anon", "iss": "supabase"})}";')
svc = cli.find_secrets(f'const k = "{jwt({"role": "service_role", "iss": "supabase"})}";')
old = cli.find_secrets(f'const k = "{jwt({"sub": "u1", "exp": 1000})}";')
check(anon and anon[0]["severity"] == "low" and anon[0]["jwt"]["role"] == "anon", "JWT role anon → low, claims decoded")
check(svc and svc[0]["severity"] == "high" and "service" in svc[0]["note"], "JWT role service_role → high")
check(old and old[0]["severity"] == "medium" and "expired" in old[0].get("note", ""), "expired JWT noted")

# ── endpoints: methods, hidden tokens ────────────────────────────────────────
EP_JS = '''
fetch("/api/users", { method: "POST", body: JSON.stringify({ name: n, email, role: r, ...rest }) });
fetch("/api/profile");
axios.delete(`/api/users/${id}`);
this.http.put("/api/v2/settings", payload);
xhr.open("PATCH", "/api/orders/7");
$.ajax({ url: "/legacy/save.php", type: "POST", data: { orderId: 1, coupon: c } });
const u = "/api/latest/devices";   const v = "/api/adminPanel/export";
const p = "/api/contest/protest";  const q = "/internal/debug/vars";
const msg = "/api failed to load";  const img = "/static/logo.png";
'''
eps = {d["path"]: d for d in cli.find_endpoints_in_files([("x.js", EP_JS, 2)])}
for path, methods in {"/api/users": ["POST"], "/api/profile": ["GET"], "/api/users/{param}": ["DELETE"],
                      "/api/v2/settings": ["PUT"], "/api/orders/7": ["PATCH"], "/legacy/save.php": ["POST"]}.items():
    check(path in eps and eps[path]["methods"] == methods, f"endpoint {path} method {methods} ({eps.get(path, {}).get('methods')})")
check(eps["/api/adminPanel/export"]["hidden"] and eps["/internal/debug/vars"]["hidden"],
      "hidden: adminPanel (camelCase) and /internal/debug flagged")
check(not eps["/api/latest/devices"]["hidden"] and not eps["/api/contest/protest"]["hidden"],
      "hidden: latest/devices/contest/protest NOT flagged (whole-token match)")
check("/api failed to load" not in eps and "/static/logo.png" not in eps, "prose with spaces and static assets dropped")
check(eps["/api/profile"]["line"] == 3 + 2 and eps["/api/profile"]["file"] == "x.js", "endpoint file:line includes header offset")

# ── params: request-only ─────────────────────────────────────────────────────
PARAM_JS = EP_JS + '''
const g = gql`query GetUser($userId: ID!, $first: Int) { user(id: $userId) { id } }`;
new URLSearchParams(location.search).get("redirect"); fd.append("avatar", file); headers.append("Content-Type", "x");
const route = "/users/:accountId/orders";
fetch("/search?q=1&page=2");
const ui = { isOpen: true, theme: "dark", onClick: f, __proto__: null };
html = `<input type="text" name="promo_code">`;
'''
params = set(cli.extract_params(PARAM_JS, '<form><input name="csrf_token"></form>'))
want = {"name", "email", "role", "orderId", "coupon", "userId", "first", "redirect", "avatar",
        "accountId", "q", "page", "promo_code", "csrf_token"}
check(want <= params, f"params: request fields found (missing: {sorted(want - params)})")
check(not ({"isOpen", "theme", "onClick", "rest", "Content-Type", "__proto__"} & params),
      f"params: UI state, spreads and header names excluded ({sorted(params - want)})")

# ── integration: results.json details, --fail-on secrets ignores low ─────────
routes = {
    "/": ('<html><script src="/app.js"></script></html>'),
    "/app.js": ('fetch("/api/admin/users", {method: "DELETE"});\n'
                'const maps = "' + T("AIza", "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY") + '";\n'),
    "/leak": '<html><script src="/leak.js"></script></html>',
    "/leak.js": 'const s = "' + T("sk_li", "ve_51H8xYzQWEmnbVCXlkjHGF9") + '";',
}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        b = routes.get(self.path)
        self.send_response(200 if b is not None else 404); self.end_headers()
        if b is not None: self.wfile.write(b.encode())
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_port}"

def run_main(argv):
    sys.argv = ["js-extractor"] + argv
    buf = io.StringIO(); code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli.main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code, buf.getvalue()

COMMON = ["--rate-limit", "0", "--no-sourcemaps", "--no-chunks"]
code, out = run_main([BASE + "/", "--endpoints", "--fail-on", "secrets", "--report",
                      "--output-dir", str(TMP / "a")] + COMMON)
res = json.loads((TMP / "a" / "results.json").read_text())
det = {d["path"]: d for d in res["endpoint_details"]}
check(det.get("/api/admin/users", {}).get("methods") == ["DELETE"] and det["/api/admin/users"]["hidden"]
      and det["/api/admin/users"]["file"].startswith("external/"), "results.json: endpoint_details with method, hidden, file")
check(code == 0 and res["secrets"] and res["secrets"][0]["severity"] == "low",
      "--fail-on secrets: a public-by-design key alone does NOT fail the gate")
rep = (TMP / "a" / "report.html").read_text()
check("DELETE" in rep and "usually a browser key" in rep, "report shows endpoint method and secret note")
code, out = run_main([BASE + "/leak", "--fail-on", "secrets", "--output-dir", str(TMP / "b")] + COMMON)
check(code == 3, "--fail-on secrets: a live Stripe secret key fails the gate")

# ── linear time on hostile input ─────────────────────────────────────────────
N = 600_000
hostile = {
    "long word": "var big='" + "x" * N + "';",
    "fetch spam": 'fetch("/a",' * (N // 11),
    "object spam": "body:{" * (N // 6),
    "colon spam": "a://b:c@" * (N // 8),
}
for name, s in hostile.items():
    t0 = time.time()
    cli.find_secrets(s); cli.find_endpoints(s); cli.extract_params(s)
    dt = time.time() - t0
    check(dt < 8, f"hostile input '{name}': secrets+endpoints+params in {dt:.2f}s")

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED")
sys.exit(1 if fails else 0)
