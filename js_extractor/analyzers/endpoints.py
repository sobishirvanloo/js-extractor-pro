"""
API endpoint extraction with HTTP methods, locations and hidden-path detection.
"""
import bisect
import re

from ..jsparse import call_args


_HTTP_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"



_EP_URL = r'''(?:https?://[^`'"\s]{3,300}|/[^`'"\s]{1,300})'''   # absolute URL or root-relative path



# (regex, how the HTTP method is known). Group "url" = endpoint, "m" = method if inline.
_ENDPOINT_RULES = [
    # fetch("/x", { method: "POST" })   — method from the options argument, GET by default
    (re.compile(r'''(?<![\w$.])fetch\s*\(\s*([`'"])(?P<url>''' + _EP_URL + r''')\1'''), "fetch"),
    # axios.post("/x") · api.get(...) · this.http.delete(...) · $.post(...) · superagent.put(...)
    (re.compile(r'''(?<![\w$])[\w$.]{1,60}\.(?P<m>get|post|put|patch|delete|head|options)\s*\(\s*([`'"])(?P<url>'''
                + _EP_URL + r''')\2''', re.I), "inline"),
    # xhr.open("POST", "/x")
    (re.compile(r'''\.open\s*\(\s*["'`](?P<m>''' + _HTTP_METHODS + r''')["'`]\s*,\s*([`'"])(?P<url>'''
                + _EP_URL + r''')\2''', re.I), "inline"),
    # { url: "/x", method/type: "POST" } (axios config, $.ajax), url/path/endpoint/baseURL assignments
    (re.compile(r'''(?<![\w$])(?:url|uri|path|endpoint|baseURL|baseUrl|apiUrl|api_url|href|action)["']?\s*[:=]\s*([`'"])(?P<url>'''
                + _EP_URL + r''')\1'''), "object"),
    # bare string literals that look like API paths
    (re.compile(r'''[`'"](?P<url>(?:/api|/v\d+|/graphql|/gql|/rest|/rpc|/internal|/admin|/auth|/oauth|/ws)'''
                r'''[^`'"\s<>{}]{1,200})[`'"]'''), None),
    # template literals with a path prefix: `/api/users/${id}`
    (re.compile(r'''`(?P<url>(?:/api|/v\d+|/internal|/admin)[^`]{1,200})`'''), None),
]



MAX_OPTION_PARSES = 2000          # per file: fetch(url, {options}) parses / request objects



_METHOD_IN_OBJ_RE = re.compile(r'''(?<![\w$])(?:method|type)\s*:\s*["'`](''' + _HTTP_METHODS + r''')["'`]''', re.I)



# Whole path tokens (split on / . _ - ? = & and camelCase) that mark sensitive endpoints.
# Token matching avoids the old substring false positives: latest, device, contest, protest...
_HIDDEN_TOKENS = {
    "internal", "debug", "admin", "administrator", "admins", "secret", "secrets", "hidden",
    "private", "test", "tests", "testing", "dev", "devel", "development", "staging", "stage",
    "backdoor", "console", "panel", "actuator", "metrics", "swagger", "backup", "backups",
    "config", "configuration", "env", "phpinfo", "trace", "manage", "management", "mgmt",
    "superuser", "sudo", "root", "beta", "qa", "sandbox", "impersonate", "export", "dump",
}



_SKIP_EXTENSIONS = re.compile(r'\.(js|mjs|css|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|eot|otf|ico|map|mp4|webm|mp3)(\?.*)?$', re.I)



def _path_tokens(path: str) -> set:
    path = re.split(r"[?#]", path)[0]
    words = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", path)   # splits camelCase too
    return {w.lower() for w in words}



def is_hidden_endpoint(path: str) -> bool:
    return bool(_path_tokens(path) & _HIDDEN_TOKENS)



def _clean_endpoint(url: str):
    """Normalise ${expr} to {param}; drop static assets, prose and junk."""
    ep = re.sub(r"\$\{[^}]{0,200}\}", "{param}", url.strip())
    if len(ep) < 2 or ep in ("//",) or re.search(r"\s", ep) or _SKIP_EXTENSIONS.search(ep):
        return None
    if ep.startswith("//"):                      # protocol-relative: not a path
        return None
    return ep



def find_endpoints(js_code: str) -> list[dict]:
    """Endpoints in one file: [{path, method or None, line}]."""
    newlines = [i for i, ch in enumerate(js_code) if ch == "\n"]
    found = []
    option_parses = 0
    for rx, how in _ENDPOINT_RULES:
        for m in rx.finditer(js_code):
            ep = _clean_endpoint(m.group("url"))
            if not ep:
                continue
            method = None
            if how == "inline":
                method = m.group("m").upper()
            elif how == "fetch" and option_parses < MAX_OPTION_PARSES:
                # Bounded: hostile input with 100k+ fetch( calls stays linear
                option_parses += 1
                args = call_args(js_code, js_code.index("(", m.start()) + 1, 600)
                mm = _METHOD_IN_OBJ_RE.search(args[1]) if len(args) > 1 else None
                method = mm.group(1).upper() if mm else "GET"
            elif how == "object":
                # method/type key in the same object literal (a few hundred chars around)
                around = js_code[max(0, m.start() - 300): m.end() + 300]
                mm = _METHOD_IN_OBJ_RE.search(around)
                method = mm.group(1).upper() if mm else None
            found.append({"path": ep, "method": method,
                          "line": bisect.bisect_left(newlines, m.start()) + 1})
    return found



def find_endpoints_in_files(files: list[tuple[str, str, int]]) -> list[dict]:
    """
    Endpoints across files, grouped by path:
      {path, methods: [...], hidden: bool, file, line, locations: [{file, line}]}
    """
    grouped = {}
    for path, text, offset in files:
        for f in find_endpoints(text):
            loc = {"file": path, "line": f["line"] + offset}
            g = grouped.setdefault(f["path"], {"path": f["path"], "methods": set(),
                                               "hidden": is_hidden_endpoint(f["path"]), **loc, "locations": []})
            if f["method"]:
                g["methods"].add(f["method"])
            if loc not in g["locations"]:
                g["locations"].append(loc)
    out = []
    for g in grouped.values():
        g["methods"] = sorted(g["methods"])
        out.append(g)
    return sorted(out, key=lambda g: g["path"])



def extract_endpoints(js_code: str) -> tuple[list[str], list[str]]:
    """Back-compat wrapper: (all endpoint paths, hidden subset) for one blob of JS."""
    details = find_endpoints_in_files([("", js_code, 0)])
    return [d["path"] for d in details], [d["path"] for d in details if d["hidden"]]

