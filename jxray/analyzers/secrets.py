"""
Secret detection: token formats, severities, entropy/placeholder filtering, JWT decoding.
"""
import base64
import bisect
import json
import math
import re
import time
from collections import defaultdict


# (label, regex with the secret in group 1, severity, generic)
#   severity: high = credential that grants access; medium = needs review;
#             low = public by design (publishable/browser keys) — still worth
#             checking their restrictions, but not a leak on their own.
#   generic:  context-based pattern → entropy + placeholder filtering applies.
# Token formats are matched case-SENSITIVELY with word boundaries (the old
# blanket IGNORECASE made `AKIA[A-Z0-9]{16}` match lowercase base64 noise).
_SECRET_RULES = [
    ("AWS Access Key ID", r'''(?<![A-Za-z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9])''', "high", False),
    ("AWS Secret Access Key", r'''(?i:aws[\w.-]{0,20}?(?:secret|sk)[\w]*)["']?\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]''', "high", False),
    ("GitHub Token", r'''(?<![\w])(gh[pousr]_[A-Za-z0-9]{36,255})''', "high", False),
    ("GitHub Fine-grained Token", r'''(?<![\w])(github_pat_[A-Za-z0-9_]{70,})''', "high", False),
    ("GitLab Token", r'''(?<![\w-])(glpat-[A-Za-z0-9_-]{20,})''', "high", False),
    ("Slack Token", r'''(?<![\w-])(xox[baprs]-[A-Za-z0-9-]{10,})''', "high", False),
    ("Slack Webhook", r'''(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)''', "high", False),
    ("Discord Webhook", r'''(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+)''', "high", False),
    ("OpenAI API Key", r'''(?<![\w-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{48})(?![\w-])''', "high", False),
    ("Anthropic API Key", r'''(?<![\w-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})''', "high", False),
    ("Stripe Secret Key", r'''(?<![\w])((?:sk|rk)_live_[A-Za-z0-9]{20,})''', "high", False),
    ("Stripe Test Secret Key", r'''(?<![\w])((?:sk|rk)_test_[A-Za-z0-9]{20,})''', "medium", False),
    ("Stripe Publishable Key", r'''(?<![\w])(pk_(?:live|test)_[A-Za-z0-9]{20,})''', "low", False),
    ("Twilio API Key", r'''(?<![A-Za-z0-9])(SK[0-9a-f]{32})(?![0-9a-f])''', "high", False),
    ("Twilio Account SID", r'''(?<![A-Za-z0-9])(AC[0-9a-f]{32})(?![0-9a-f])''', "low", False),
    ("SendGrid API Key", r'''(?<![\w])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})''', "high", False),
    ("Mailgun API Key", r'''(?<![\w-])(key-(?=[0-9a-z]{0,31}\d)[0-9a-z]{32})(?![0-9a-z])''', "high", False),
    ("Mailchimp API Key", r'''(?<![0-9a-f])([0-9a-f]{32}-us\d{1,2})(?!\d)''', "high", False),
    ("npm Token", r'''(?<![\w])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])''', "high", False),
    ("PyPI Token", r'''(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})''', "high", False),
    ("Shopify Token", r'''(?<![\w])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})''', "high", False),
    ("Telegram Bot Token", r'''(?<![\d])(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![\w-])''', "high", False),
    ("Square Token", r'''(?<![\w-])(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43})''', "high", False),
    ("Facebook Access Token", r'''(?<![A-Za-z0-9])(EAA[A-Za-z0-9]{80,})''', "high", False),
    ("Azure Storage Connection String", r'''(DefaultEndpointsProtocol=https?;AccountName=[^;"'\s]+;AccountKey=[A-Za-z0-9+/=]{40,})''', "high", False),
    ("Private Key", r'''(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)''', "high", False),
    ("Mapbox Secret Token", r'''(?<![\w])(sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})''', "high", False),
    ("Credentials in URL", r'''(?<![\w+.-])([a-z][a-z0-9+.-]{1,20}://[^\s/:@"'`<>]{1,64}:[^\s/@"'`<>]{1,128}@[A-Za-z0-9.-]+\.[A-Za-z]{2,})''', "high", True),
    ("JWT", r'''(?<![\w-])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})''', "medium", False),
    ("Mapbox Public Token", r'''(?<![\w])(pk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})''', "low", False),
    ("Google API Key", r'''(?<![\w-])(AIza[A-Za-z0-9_-]{35})(?![\w-])''', "low", False),
    ("Sentry DSN", r'''(https://[0-9a-f]{32}@[\w.-]*sentry\.io/\d+)''', "low", False),
    ("Firebase Database URL", r'''(https://[a-z0-9-]+\.firebaseio\.com)''', "low", False),
    # generic, context-based → entropy + placeholder filtered
    ("API Key", r'''(?i:api[_-]?key|apikey|x-api-key|api[_-]?secret|access[_-]?key)["']?\s*[:=]\s*["'`]([A-Za-z0-9_\-]{16,128})["'`]''', "medium", True),
    ("Secret", r'''(?i:secret|client[_-]?secret|app[_-]?secret)["']?\s*[:=]\s*["'`]([^"'`\s]{8,128})["'`]''', "medium", True),
    ("Password", r'''(?i:password|passwd|pwd)["']?\s*[:=]\s*["'`]([^"'`\s]{6,128})["'`]''', "medium", True),
    ("Bearer Token", r'''["'`]Bearer\s+([A-Za-z0-9\-_.=~+/]{20,})["'`]''', "medium", True),
    ("Hex Secret", r'''(?i:secret|token|key)["']?\s*[:=]\s*["'`]([0-9a-fA-F]{32,})["'`]''', "medium", True),
]



_SECRET_RES = [(label, re.compile(rx), sev, generic) for label, rx, sev, generic in _SECRET_RULES]



_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}



_LOW_NOTES = {
    "Google API Key": "usually a browser key (Firebase/Maps) — check its API & referrer restrictions",
    "Stripe Publishable Key": "publishable by design",
    "Mapbox Public Token": "public by design — check its URL restrictions",
    "Sentry DSN": "public by design; allows sending events to the project",
    "Firebase Database URL": "check the database rules: try <url>/.json",
    "Twilio Account SID": "an identifier, not a secret on its own — look for the auth token nearby",
}



_PLACEHOLDER_RE = re.compile(
    r"(?i)your|example|sample|dummy|placeholder|changeme|change_me|redacted|insert|replace|"
    r"xxxx|\*{3,}|<[^>]*>|\$\{|\{\{|process\.env|todo|fixme|lorem|abcdef|123456|qwerty")



_PLACEHOLDER_WORDS = {"password", "passwd", "secret", "token", "apikey", "api_key", "null",
                      "undefined", "true", "false", "none", "pass", "user", "username", "admin123"}



def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())



def _looks_placeholder(v: str) -> bool:
    low = v.lower()
    return bool(
        _PLACEHOLDER_RE.search(v)
        or low in _PLACEHOLDER_WORDS
        or len(set(low)) <= 3                                   # aaaaaaaa, 00000000
        or (re.fullmatch(r"[A-Z0-9_]+", v) and "_" in v)        # ENV_VAR_NAME
        or re.fullmatch(r"[A-Za-z]+(?:[._-][A-Za-z]+)+", v)     # i18n keys / field names: auth.password, new-password
    )



def _generic_secret_ok(label: str, v: str) -> bool:
    """Filters for context-based patterns, where the value could be anything."""
    if label == "Credentials in URL":
        m = re.match(r"[^:]+://([^:]*):([^@]*)@([^/]+)", v)
        if not m:
            return False
        user, pw, host = m.groups()
        return not (_looks_placeholder(pw) or pw.lower() in {"pass", "password", "pwd", "secret"}
                    or re.search(r"(?i)example\.(?:com|org|net)$", host))
    if _looks_placeholder(v):
        return False
    if label == "Password":
        return True                     # real passwords are low-entropy; placeholder filter only
    # random keys: some entropy and both letters and digits
    return (_shannon_entropy(v) >= 3.0 and re.search(r"\d", v) is not None
            and re.search(r"[A-Za-z]", v) is not None)



def _jwt_claims(token: str):
    try:
        payload = token.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return data if isinstance(data, dict) else None
    except (ValueError, IndexError):
        return None



def find_secrets(js_code: str) -> list[dict]:
    """
    Scan JS source for leaked credentials/tokens.

    Returns [{type, value, line, severity, note?, jwt?}] (line is 1-based within js_code).
    """
    # Offsets of every newline, so each match's line is a binary search
    # instead of re-counting the whole prefix (quadratic on big bundles).
    newlines = [i for i, ch in enumerate(js_code) if ch == "\n"]
    results = []
    seen = set()

    for label, rx, severity, generic in _SECRET_RES:
        for m in rx.finditer(js_code):
            val = m.group(1)
            # Dedupe on the full value: a 30-char prefix collapsed distinct
            # JWTs, which all share the same encoded header.
            # Rules run specific → generic, so a value already claimed by a
            # specific rule (or an earlier generic one) isn't reported twice.
            if val in seen or (generic and not _generic_secret_ok(label, val)):
                continue
            seen.add(val)
            finding = {"type": label, "value": val, "severity": severity,
                       "line": bisect.bisect_left(newlines, m.start()) + 1}
            if label in _LOW_NOTES:
                finding["note"] = _LOW_NOTES[label]
            if label == "JWT":
                claims = _jwt_claims(val)
                if claims is not None:
                    finding["jwt"] = {k: claims[k] for k in ("iss", "role", "sub", "aud", "exp") if k in claims}
                    role = str(claims.get("role", "")).lower()
                    if role in ("service_role", "supabase_admin", "admin"):
                        finding["severity"] = "high"
                        finding["note"] = f"privileged role '{role}' (e.g. Supabase service key bypasses RLS)"
                    elif role == "anon":
                        finding["severity"] = "low"
                        finding["note"] = "anonymous role — public by design (e.g. Supabase anon key)"
                    exp = claims.get("exp")
                    if isinstance(exp, (int, float)) and exp < time.time():
                        finding["note"] = (finding.get("note", "") + "; expired").lstrip("; ")
            results.append(finding)

    return results



def find_secrets_in_files(files: list[tuple[str, str, int]]) -> list[dict]:
    """
    Run find_secrets() per file so every finding points at a real file and
    line on disk. `files` is a list of (display_path, text, header_lines),
    where header_lines is how many lines save_js() prepended on disk.

    The same secret often appears in several places (the minified bundle AND
    its recovered original source), so findings are grouped by (type, value):
      { type, value, file, line, locations: [{file, line}, ...] }
    with file/line being the first location.
    """
    grouped = {}
    for path, text, offset in files:
        for f in find_secrets(text):
            loc = {"file": path, "line": f["line"] + offset}
            key = (f["type"], f["value"])
            if key not in grouped:
                grouped[key] = {**{k: v for k, v in f.items() if k != "line"}, **loc, "locations": []}
            grouped[key]["locations"].append(loc)
    return sorted(grouped.values(), key=lambda s: (_SEVERITY_ORDER[s["severity"]], s["file"], s["line"]))



def mask_secret(val: str) -> str:
    """Show only a small prefix/suffix of a secret; never most of a short one."""
    n = len(val)
    head, tail = min(6, n // 4), min(4, n // 6)
    return val[:head] + "..." + (val[-tail:] if tail else "")

