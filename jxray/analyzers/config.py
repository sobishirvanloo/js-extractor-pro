"""
Embedded configuration recon: pull the config objects, feature flags, internal
hosts, cloud resources and env-var names that SPAs bake into their bundles.

These aren't "secrets" (that analyzer covers credentials) but they map the
application's intended surface: internal hostnames, tenant IDs, debug switches,
hidden features behind flags, and which backend services it talks to.
"""
import bisect
import re

MAX_HITS = 4000            # per file: hostile-input guard
_PREVIEW = 240             # chars of a config object we keep as a preview


# Well-known global state/config objects SPAs expose on window.
_GLOBAL_NAMES = (
    r'__(?:NEXT_DATA|NUXT|INITIAL_STATE|APOLLO_STATE|PRELOADED_STATE|ENV|CONFIG|'
    r'RUNTIME_CONFIG|APP_CONFIG|ENVIRONMENT|REDUX_STATE)__'
)
_GLOBAL_ASSIGN_RE = re.compile(
    r'''(?P<name>(?:window|globalThis|self|global)\.(?:''' + _GLOBAL_NAMES + r'''|[A-Za-z_]\w*(?:[Cc]onfig|Settings|[Ee]nv)))\s*=\s*(?P<open>\{)''')
# Firebase initialisation object (apiKey + a Firebase-specific sibling key).
_FIREBASE_RE = re.compile(
    r'\{[^{}]*?authDomain\s*:\s*["\'][^"\']+\.firebaseapp\.com["\'][^{}]*?\}', re.S)

# Feature flags: boolean-valued keys whose name reads like a flag.
_FLAG_RE = re.compile(
    r'''(?<![\w$])["']?(?P<key>(?:enable|disable|is|has|allow|show|hide|use|feature|flag|ff|
        beta|experimental|debug|canary|preview|rollout)[A-Za-z0-9_]{1,40})["']?\s*:\s*(?P<val>true|false)''',
    re.X | re.I)

# Internal / non-routable hosts and cloud metadata.
_INTERNAL_HOST_RE = re.compile(
    r'''(?<![\w.])(?:
        (?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}
          |192\.168\.\d{1,3}\.\d{1,3}
          |172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}
          |127\.\d{1,3}\.\d{1,3}\.\d{1,3}
          |169\.254\.169\.254)                       # cloud metadata
      | https?://[a-z0-9.-]+\.(?:internal|local|corp|intranet|lan|test|localhost)(?::\d+)?
    )(?:[/:][^\s"'`<>]{0,120})?''', re.I | re.X)

# Cloud storage / backend service references.
_CLOUD_RE = re.compile(
    r'''(?<![\w.])(?:
        [a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com
      | s3://[a-z0-9.\-/]+
      | [a-z0-9.\-]+\.blob\.core\.windows\.net
      | storage\.googleapis\.com/[a-z0-9.\-/]+
      | gs://[a-z0-9.\-/]+
      | [a-z0-9.\-]+\.(?:firebaseio\.com|appspot\.com)
      | [a-z0-9.\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com
    )''', re.I | re.X)

_ENV_VAR_RE = re.compile(r'''process\.env\.(?P<name>[A-Z][A-Z0-9_]{2,60})''')


def _preview_object(js_code: str, open_idx: int) -> str:
    """Truncated text of the object literal starting at the '{' at open_idx."""
    depth = 0
    for i in range(open_idx, min(len(js_code), open_idx + 6000)):
        c = js_code[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                text = js_code[open_idx:i + 1]
                return (text[:_PREVIEW] + "…") if len(text) > _PREVIEW else text
    return js_code[open_idx:open_idx + _PREVIEW] + "…"


def find_config(js_code: str) -> list[dict]:
    """Config findings in one file: [{kind, name, value, line}].
    kind ∈ config-object | feature-flag | internal-host | cloud-resource | env-var."""
    newlines = [i for i, ch in enumerate(js_code) if ch == "\n"]
    line_at = lambda pos: bisect.bisect_left(newlines, pos) + 1
    out, seen, n = [], set(), 0

    def add(kind, name, value, pos):
        nonlocal n
        if n >= MAX_HITS:
            return
        key = (kind, name, value)
        if key in seen:
            return
        seen.add(key)
        n += 1
        out.append({"kind": kind, "name": name, "value": value, "line": line_at(pos)})

    for m in _GLOBAL_ASSIGN_RE.finditer(js_code):
        add("config-object", m.group("name"), _preview_object(js_code, m.start("open")), m.start())
    for m in _FIREBASE_RE.finditer(js_code):
        text = m.group(0)
        add("config-object", "firebaseConfig",
            (text[:_PREVIEW] + "…") if len(text) > _PREVIEW else text, m.start())
    for m in _FLAG_RE.finditer(js_code):
        add("feature-flag", m.group("key"), m.group("val").lower(), m.start())
    for m in _INTERNAL_HOST_RE.finditer(js_code):
        add("internal-host", "", m.group(0).strip().rstrip(".,;)"), m.start())
    for m in _CLOUD_RE.finditer(js_code):
        add("cloud-resource", "", m.group(0).strip(), m.start())
    for m in _ENV_VAR_RE.finditer(js_code):
        add("env-var", m.group("name"), "", m.start())
    return out


def find_config_in_files(files: list[tuple[str, str, int]]) -> list[dict]:
    """Config findings across files, grouped by (kind, name, value) with
    file:line locations — same shape as the secret/endpoint analyzers."""
    grouped = {}
    for path, text, offset in files:
        for f in find_config(text):
            key = (f["kind"], f["name"], f["value"])
            loc = {"file": path, "line": f["line"] + offset}
            g = grouped.setdefault(key, {**{k: v for k, v in f.items() if k != "line"},
                                         **loc, "locations": []})
            if loc not in g["locations"]:
                g["locations"].append(loc)
    order = {"config-object": 0, "feature-flag": 1, "internal-host": 2, "cloud-resource": 3, "env-var": 4}
    return sorted(grouped.values(), key=lambda g: (order.get(g["kind"], 9), g["name"], g["value"]))
