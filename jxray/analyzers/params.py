"""
Request parameter extraction for fuzzing wordlists.
"""
import re

from ..analyzers.endpoints import MAX_OPTION_PARSES
from ..jsparse import scan_js_expr, split_top_level


# Only names that actually reach a request. The old "every {key:" pattern
# turned the wordlist into thousands of React/webpack internals.
_PNAME = r'''[A-Za-z_$][\w$\-\[\].]{0,40}'''



_PARAM_RES = [
    # query strings: ?foo=  &bar=
    re.compile(r'''[?&](''' + _PNAME + r''')='''),
    # URLSearchParams / FormData style access on param-ish receivers
    re.compile(r'''(?<![\w$])(?:searchParams|urlParams|params|query|qs|formData|fd|form|payload)\s*\.\s*'''
               r'''(?:get|getAll|has|set|append|delete)\s*\(\s*["'`](''' + _PNAME + r''')["'`]'''),
    # new URLSearchParams(location.search).get("redirect")
    re.compile(r'''URLSearchParams\s*\([^()]{0,200}\)\s*\.\s*(?:get|getAll|has)\s*\(\s*["'`](''' + _PNAME + r''')["'`]'''),
    # FormData / URLSearchParams .append/.set("name", value) — two-argument form
    re.compile(r'''\.(?:append|set)\s*\(\s*["'`](''' + _PNAME + r''')["'`]\s*,'''),
    # route params inside path strings: /users/:id
    re.compile(r'''/:([A-Za-z_]\w{0,40})(?=[/"'`?)]|$)'''),
    # GraphQL operation variables: query($id: ID!, $first: Int)
    re.compile(r'''\$([A-Za-z_]\w{0,40})\s*:\s*\[?\s*[A-Z]\w*'''),
    # form fields in HTML or HTML-in-JS
    re.compile(r'''<(?:input|select|textarea|button)\b[^>]{0,300}?\bname\s*=\s*\\?["']([^"'\\\s]{1,40})''', re.I),
]



# Where an object literal is a request payload: its top-level keys are params
_PARAM_OBJ_RES = [
    re.compile(r'''(?<![\w$])(?:params|data|body|json|query|variables|searchParams|qs|form|payload)\s*:\s*(?=\{)'''),
    re.compile(r'''(?:JSON\.stringify|(?<![\w$])stringify|URLSearchParams)\s*\(\s*(?=\{)'''),
    re.compile(r'''\.(?:post|put|patch)\s*\(\s*[^,()]{1,300},\s*(?=\{)'''),
]



# Language noise only — real field names like name/type/data/value are kept now
_PARAM_NOISE = {w.lower() for w in (
    "function", "return", "const", "let", "var", "class", "import", "export", "default",
    "true", "false", "null", "undefined", "this", "new", "typeof", "prototype",
    "constructor", "toString", "valueOf", "hasOwnProperty", "length", "__proto__",
    # built-in method names: never real request fields
    "forEach", "map", "filter", "reduce", "push", "pop", "then", "catch", "apply", "call", "bind",
)}



# Header names passed to Headers.append/set are not fuzzable params
_HEADER_NAME_RE = re.compile(r"^(?:[A-Z][a-z0-9]*(?:-[A-Z][a-z0-9]*)+|[Xx]-[\w-]+|content-type|authorization|accept)$")



def _object_keys(obj: str) -> list[str]:
    """Top-level keys of a JS object literal "{a: 1, 'b': 2, c, ...d}"."""
    inner = obj.strip()
    if not (inner.startswith("{") and inner.endswith("}")):
        return []
    keys = []
    for part in split_top_level(inner[1:-1], ","):
        part = part.strip()
        if not part or part.startswith("..."):
            continue
        key = split_top_level(part, ":")[0].strip()
        key = key.strip("\"'`")
        if re.fullmatch(_PNAME, key) and not key.startswith("["):
            keys.append(key)
    return keys



def extract_params(js_code: str, html_code: str = "") -> list[str]:
    """
    Extract request parameter names from JS (and optionally HTML) for fuzzing.
    Returns a deduplicated, sorted list.
    """
    found = set()
    for text in (js_code, html_code):
        if not text:
            continue
        for rx in _PARAM_RES:
            for m in rx.finditer(text):
                found.add(m.group(1).strip())
        for i, m in enumerate(rx_m for rx in _PARAM_OBJ_RES for rx_m in rx.finditer(text)):
            if i >= MAX_OPTION_PARSES:
                break
            found.update(_object_keys(scan_js_expr(text, m.end(), 3000)))

    return sorted((p for p in found
                   if 1 <= len(p) <= 40 and p.lower() not in _PARAM_NOISE and not _HEADER_NAME_RE.match(p)),
                  key=str.lower)

