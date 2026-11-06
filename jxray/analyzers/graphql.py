"""
GraphQL recon: pull operations (query / mutation / subscription), fragments and
client endpoints out of bundled JS.

SPAs ship their whole GraphQL surface in the client bundle — operation names,
the exact fields each one selects, and the transport URL — which is a far
richer map than the REST endpoint list. Extraction is static (regex + brace
matching); an optional introspection probe against a discovered endpoint lives
in cli, reusing the scoped session.
"""
import bisect
import re

# GraphQL structural keywords that are never field names — dropped from the
# "root fields" list so it carries only real selection fields.
_GQL_KW = {
    "query", "mutation", "subscription", "fragment", "on", "true", "false", "null",
    "type", "input", "enum", "interface", "union", "scalar", "schema", "directive",
}

_OP_RE = re.compile(r'(?<![\w$])(?P<type>query|mutation|subscription)\b\s*(?P<name>[A-Za-z_]\w*)?\s*(?:\([^{]*?\))?\s*\{')
_FRAGMENT_RE = re.compile(r'(?<![\w$])fragment\s+(?P<name>[A-Za-z_]\w*)\s+on\s+(?P<onType>[A-Za-z_]\w*)\s*\{')
# gql`...` / graphql`...` / graphql-tag tagged templates (content is GraphQL)
_TAG_RE = re.compile(r'(?<![\w$])(?:gql|graphql)\s*`')
# Apollo / urql / relay client transport URLs
_CLIENT_URI_RE = re.compile(
    r'''(?:uri|url|endpoint|graphqlEndpoint|httpEndpoint)\s*:\s*["'`](?P<url>https?://[^"'`]{3,300}|/[^"'`\s]{1,300})["'`]''')
_PATH_HINT_RE = re.compile(r'''["'`](?P<url>(?:https?://[^"'`\s]+)?/(?:graphql|gql|api/graphql|query)(?:/[^"'`\s]*)?)["'`]''', re.I)

MAX_OPS = 2000             # per file: hostile-input guard
MAX_BODY = 20000           # chars of one operation body we bother parsing


def _match_brace(s: str, open_idx: int) -> int:
    """Index just past the '}' matching the '{' at open_idx, or -1. Best-effort:
    does not track string literals (GraphQL bodies rarely brace inside strings)."""
    depth = 0
    for i in range(open_idx, min(len(s), open_idx + MAX_BODY)):
        c = s[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _root_fields(body_inner: str) -> list[str]:
    """Top-level selection fields: identifiers at brace/paren depth 0 of the
    operation body (nested selections and argument lists are skipped)."""
    depth, kept = 0, []
    for c in body_inner:
        if c in "{(":
            depth += 1
        elif c in "})":
            depth = max(0, depth - 1)
        elif depth == 0:
            kept.append(c)
    names, seen = [], set()
    for n in re.findall(r"[A-Za-z_]\w*", "".join(kept)):
        if n not in _GQL_KW and n not in seen:
            seen.add(n)
            names.append(n)
    return names


def find_graphql(js_code: str) -> dict:
    """Operations, fragments and endpoints in one blob of JS.
    Returns {operations: [...], fragments: [...], endpoints: [...]}."""
    newlines = [i for i, ch in enumerate(js_code) if ch == "\n"]
    line_at = lambda pos: bisect.bisect_left(newlines, pos) + 1

    # Scan both the raw code and the inside of gql`...` templates; a template's
    # offset is tracked so operation line numbers stay correct.
    segments = [(js_code, 0)]
    for m in _TAG_RE.finditer(js_code):
        start = m.end()
        end = js_code.find("`", start)
        if end != -1:
            segments.append((js_code[start:end], start))

    operations, fragments = [], []
    ops_seen = set()
    n_ops = 0
    for text, base in segments:
        for m in _OP_RE.finditer(text):
            if n_ops >= MAX_OPS:
                break
            n_ops += 1
            brace = base + m.end() - 1          # position of '{' in js_code
            close = _match_brace(js_code, brace)
            body_inner = js_code[brace + 1: close - 1] if close != -1 else ""
            name = m.group("name") or "(anonymous)"
            key = (m.group("type"), name, line_at(base + m.start()))
            if key in ops_seen:
                continue
            ops_seen.add(key)
            operations.append({
                "type": m.group("type"),
                "name": name,
                "fields": _root_fields(body_inner)[:40],
                "line": line_at(base + m.start()),
            })
        for m in _FRAGMENT_RE.finditer(text):
            fragments.append({"name": m.group("name"), "on": m.group("onType"),
                              "line": line_at(base + m.start())})

    endpoints = {}
    for rx in (_CLIENT_URI_RE, _PATH_HINT_RE):
        for m in rx.finditer(js_code):
            url = m.group("url")
            endpoints.setdefault(url, line_at(m.start()))
    endpoint_list = [{"url": u, "line": ln} for u, ln in endpoints.items()]

    return {"operations": operations, "fragments": fragments, "endpoints": endpoint_list}


def find_graphql_in_files(files: list[tuple[str, str, int]]) -> dict:
    """Aggregate GraphQL findings across files, each tagged with file:line.
    Operations are de-duplicated by (type, name)."""
    ops, frags, eps = {}, {}, {}
    for path, text, offset in files:
        res = find_graphql(text)
        for o in res["operations"]:
            key = (o["type"], o["name"])
            g = ops.setdefault(key, {**o, "file": path, "line": o["line"] + offset,
                                     "fields": list(o["fields"]), "locations": []})
            # keep the union of fields seen for this operation name
            for f in o["fields"]:
                if f not in g["fields"]:
                    g["fields"].append(f)
            loc = {"file": path, "line": o["line"] + offset}
            if loc not in g["locations"]:
                g["locations"].append(loc)
        for fr in res["fragments"]:
            frags.setdefault((fr["name"], fr["on"]),
                             {**fr, "file": path, "line": fr["line"] + offset})
        for e in res["endpoints"]:
            eps.setdefault(e["url"], {"url": e["url"], "file": path, "line": e["line"] + offset})

    return {
        "operations": sorted(ops.values(), key=lambda o: (o["type"], o["name"])),
        "fragments": sorted(frags.values(), key=lambda f: f["name"]),
        "endpoints": sorted(eps.values(), key=lambda e: e["url"]),
    }


# ── Optional active introspection ─────────────────────────────────────────────
INTROSPECTION_QUERY = (
    "query IntrospectionQuery{__schema{queryType{name}mutationType{name}"
    "subscriptionType{name}types{name kind}}}"
)


def parse_introspection(data: dict) -> dict | None:
    """Summarise an introspection response into
    {query_type, mutation_type, subscription_type, type_count, types:[...]}."""
    schema = (data or {}).get("data", {}).get("__schema")
    if not schema:
        return None
    types = [t.get("name") for t in schema.get("types", [])
             if t.get("name") and not t["name"].startswith("__")]
    return {
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
        "type_count": len(types),
        "types": sorted(types)[:200],
    }
