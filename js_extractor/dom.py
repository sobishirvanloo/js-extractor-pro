"""
DOM XSS taint analysis for client-side JavaScript (--dom).

A static triage map — where attacker-influenced data can reach an HTML,
code, script-URL or navigation sink — built without a JS parser, in bounded
linear time so hostile multi-MB bundles stay fast. It does NOT prove
exploitability: every finding is a lead to confirm by hand (e.g. with
Burp's DOM Invader).

Per file:
  1. Sources: URL (location.*, document.URL, URLSearchParams(location)),
     framework routing (Vue $route, Next/React router hooks, Angular
     ActivatedRoute), referrer, window.name, cookies, web storage, and
     postMessage data inside message handlers.
  2. Sinks, each with a kind: html, code, script-url, nav, nav-app,
     storage-write, cookie-write, framework (bypassSecurityTrust*), plus
     elements created with document.createElement('script'|'iframe'|...)
     whose src/href/action is assigned.
  3. Taint propagation in source order through assignments (incl.
     destructuring and +=), killed by clean reassignment and expiring after
     a distance (minified bundles reuse short names everywhere).
  4. One level of inter-procedural flow: a function whose parameter reaches
     a sink is reported when it is called with tainted data.
  5. Sanitizers (DOMPurify.sanitize, encodeURIComponent, escape*, numeric
     casts) and constant URL prefixes lower the severity instead of hiding
     the finding; message handlers are classified by their origin check
     (none / weak substring-style / strict).

Each finding carries a trace (source → hops → sink, with lines), a
severity and a confidence.
"""
import bisect
import re

from .jsparse import (IDENT_RE, brace_map, call_args_span, is_constant_expr,
                      scan_js_expr_span, split_top_level, strip_parens)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

MAX_FINDINGS_PER_FILE = 500
MAX_SOURCES_PER_FILE = 1000
MAX_FUNCTIONS = 5000
MAX_ASSIGNMENTS = 40000
MAX_HANDLERS = 200
MAX_CALL_SITES = 2000
ARG_LIMIT = 5000              # sink argument scan
RHS_LIMIT = 250               # assignment right-hand side scan
ARROW_BODY_LIMIT = 400        # expression-bodied arrow functions
MAX_SINKS_PER_PARAM = 10      # function summary entries per (name, parameter)
TAINT_DISTANCE = 8000         # chars a tainted variable stays "in scope"
SHORT_NAME_DISTANCE = 1500    # …for 1–2 char names (minifier output)

# ── sources ──────────────────────────────────────────────────────────────────
# (label, category, regex). Categories that the attacker controls directly
# (url, framework-route, referrer, window-name, message) rank above stored
# values (storage, cookie), which need a prior write.
_SOURCES = [
    ("location", "url",
     r'''(?<![\w$])(?:(?:window|document|self|top|parent)\s*\.\s*)?location\s*\.\s*(?:hash|search|href|pathname)\b'''),
    ("document.URL", "url", r'''(?<![\w$])document\s*\.\s*(?:URL|documentURI|baseURI)\b'''),
    ("URLSearchParams(location)", "url",
     r'''URLSearchParams\s*\(\s*(?:(?:window|document)\s*\.\s*)?location'''),
    ("new URL(location)", "url",
     r'''new\s+URL\s*\(\s*(?:(?:window|document)\s*\.\s*)?location[^()]{0,60}\)\s*\.\s*(?:searchParams|hash|search)'''),
    ("searchParams.get()", "url", r'''(?<![\w$])searchParams\s*\.\s*(?:get|getAll)\s*\('''),
    ("history.state", "url", r'''(?<![\w$])history\s*\.\s*state\b'''),
    ("document.referrer", "referrer", r'''(?<![\w$])document\s*\.\s*referrer\b'''),
    ("window.name", "window-name", r'''(?<![\w$])(?:window|self|top)\s*\.\s*name\b(?!\s*=(?!=))'''),
    ("document.cookie", "cookie", r'''(?<![\w$])document\s*\.\s*cookie\b(?!\s*=(?!=))'''),
    ("web storage", "storage",
     r'''(?<![\w$])(?:window\s*\.\s*)?(?:localStorage|sessionStorage)\s*(?:\.\s*getItem\s*\(|\[)'''),
    ("Vue $route", "framework-route", r'''\$route\s*\.\s*(?:query|params|hash|fullPath)\b'''),
    ("router.query", "framework-route",
     r'''(?<![\w$])(?:router|useRouter\s*\(\s*\))\s*\.\s*(?:query|asPath)\b'''),
    ("useSearchParams()", "framework-route", r'''(?<![\w$.])useSearchParams\s*\(\s*\)'''),
    ("useParams()", "framework-route", r'''(?<![\w$.])useParams\s*\(\s*\)'''),
    ("useLocation()", "framework-route", r'''(?<![\w$.])useLocation\s*\(\s*\)'''),
    ("Angular ActivatedRoute", "framework-route",
     r'''snapshot\s*\.\s*(?:queryParams|params|fragment|queryParamMap|paramMap)\b'''
     r'''|(?:queryParamMap|paramMap)\s*\.\s*get\s*\('''
     r'''|\.\s*(?:queryParams|fragment)\s*\.\s*(?:subscribe|pipe)\s*\('''),
]
_SOURCE_RES = [(label, cat, re.compile(rx)) for label, cat, rx in _SOURCES]
# One search finds the leftmost source AND which one it is (via lastgroup)
_ANY_SOURCE_RE = re.compile("|".join(f"(?P<s{i}>{rx})" for i, (_, _, rx) in enumerate(_SOURCES)))
# Plain substrings every source contains: `kw in expr` runs in C, so the
# (much slower) combined regex only runs on the rare expressions that pass.
_SOURCE_KEYWORDS = ("location", "document", "URLSearchParams", "URL", "searchParams", "history",
                    "name", "Storage", "$route", "router", "Router", "useSearchParams", "useParams",
                    "useLocation", "snapshot", "aramMap", "queryParams", "fragment")


def _may_have_source(expr: str) -> bool:
    return any(k in expr for k in _SOURCE_KEYWORDS)
_STORED = {"storage", "cookie"}
_CATEGORY_RANK = {"url": 0, "framework-route": 0, "message": 0, "referrer": 1,
                  "window-name": 1, "storage": 2, "cookie": 2}

# ── sanitizers ───────────────────────────────────────────────────────────────
_SANITIZER_RE = re.compile(
    r'''(?<![\w$])(?:DOMPurify\s*\.\s*sanitize|sanitize(?:Html|HTML|Url|URL)?|escape(?:Html|HTML|Attr|Attribute)?'''
    r'''|htmlEscape|encodeHTML|encodeURIComponent|encodeURI|filterXSS|xssFilter|_\s*\.\s*escape|he\s*\.\s*encode'''
    r'''|validator\s*\.\s*escape|parseInt|parseFloat|Number|Boolean|Math\s*\.\s*\w+)\s*\(''')

# ── sinks ────────────────────────────────────────────────────────────────────
# (label, kind, regex ending where the argument starts, mode, only_tainted)
#   mode: "rhs" assignment value | "expr" expression at match end | int = n-th argument | "allargs"
#   only_tainted: very common in normal code → reported only with a tainted argument
_SINKS = [
    ("innerHTML", "html", r'''\.(?:inner|outer)HTML\s*\+?=(?!=)\s*''', "rhs", False),
    ("insertAdjacentHTML", "html", r'''\.insertAdjacentHTML\s*\(\s*''', 1, False),
    ("document.write", "html", r'''(?<![\w$])document\s*\.\s*write(?:ln)?\s*\(\s*''', 0, False),
    ("createContextualFragment", "html", r'''\.createContextualFragment\s*\(\s*''', 0, False),
    ("setHTMLUnsafe/parseHTMLUnsafe", "html", r'''\.(?:setHTMLUnsafe|parseHTMLUnsafe)\s*\(\s*''', 0, False),
    ("srcdoc", "html", r'''\.srcdoc\s*=(?!=)\s*''', "rhs", False),
    ("dangerouslySetInnerHTML", "html", r'''dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*''', "expr", False),
    ("v-html / innerHTML prop", "html", r'''(?<![\w$."'])innerHTML\s*:\s*''', "expr", False),
    ("Angular [innerHTML] binding", "html-sanitized",
     r'''ɵɵ(?:dom)?[Pp]roperty\s*\(\s*["']innerHTML["']\s*,\s*''', "expr", False),
    ("jQuery .html()", "html", r'''\.html\(\s*(?=[^)\s])''', 0, False),
    ("jQuery DOM insertion", "html",
     r'''(?<![\w$.])(?:\$|jQuery)\s*\([^()]{0,200}\)\s*\.\s*(?:append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner)\s*\(\s*(?=[^)\s])''',
     0, False),
    ("jQuery $(…) selector/HTML", "html", r'''(?<![\w$.])(?:\$|jQuery)\s*\(\s*(?=[^)\s])''', 0, True),
    ("parseHTML", "html", r'''\.parseHTML\s*\(\s*''', 0, False),
    ("DOMParser.parseFromString", "html", r'''\.parseFromString\s*\(\s*''', 0, True),
    ("eval", "code", r'''(?<![\w$.])eval\s*\(\s*''', 0, False),
    ("Function()", "code", r'''(?<![\w$.])(?:new\s+)?Function\s*\(\s*(?=[^)\s])''', "allargs", False),
    ("setTimeout/setInterval string", "code", r'''(?<![\w$])set(?:Timeout|Interval)\s*\(\s*(?=["'`])''', 0, False),
    ("setTimeout/setInterval", "code", r'''(?<![\w$])set(?:Timeout|Interval)\s*\(\s*(?![\s"'`])''', 0, True),
    ("execScript/globalEval", "code",
     r'''(?<![\w$])(?:execScript|(?:\$|jQuery)\s*\.\s*globalEval)\s*\(\s*''', 0, False),
    ("Worker/importScripts URL", "script-url", r'''(?<![\w$.])(?:new\s+(?:Shared)?Worker|importScripts)\s*\(\s*''', 0, True),
    ("dynamic import()", "script-url", r'''(?<![\w$.])import\s*\(\s*(?=[^)\s])''', 0, True),
    ("location assignment", "nav",
     r'''(?<![\w$.])(?:(?:window|document|self|top|parent)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?!=)\s*''', "rhs", False),
    ("location.assign/replace", "nav", r'''(?<![\w$])location\s*\.\s*(?:assign|replace)\s*\(\s*''', 0, False),
    ("window.open", "nav", r'''(?<![\w$])window\s*\.\s*open\s*\(\s*''', 0, False),
    ("setAttribute(dangerous)", "nav",
     r'''\.setAttribute\s*\(\s*["'](?P<attr>src|href|action|formaction|srcdoc|on[a-z]+)["']\s*,\s*''', "expr", False),
    ("Angular bypassSecurityTrust", "framework",
     r'''bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*''', 0, False),
    ("router.navigateByUrl", "nav-app", r'''\.navigateByUrl\s*\(\s*''', 0, True),
    ("web storage write", "storage-write",
     r'''(?<![\w$])(?:window\s*\.\s*)?(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*''', 1, True),
    ("document.cookie write", "cookie-write", r'''(?<![\w$])document\s*\.\s*cookie\s*=(?!=)\s*''', "rhs", True),
]
_SINK_RES = [(label, kind, re.compile(rx), mode, only) for label, kind, rx, mode, only in _SINKS]

# document.createElement('script'|...) → assignments to its URL property are sinks
_CREATE_EL_RE = re.compile(
    r'''(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*document\s*\.\s*createElement\s*\(\s*["'](script|iframe|a|form|embed|object|base)["']''')
_ELEMENT_SINK_KIND = {("script", "src"): "script-url", ("base", "href"): "script-url",
                      ("iframe", "src"): "nav", ("embed", "src"): "nav", ("object", "data"): "nav",
                      ("form", "action"): "nav", ("a", "href"): "nav-click"}

# ── message handlers ─────────────────────────────────────────────────────────
_MSG_LISTEN_RE = re.compile(r'''addEventListener\s*\(\s*["']message["']\s*,\s*|(?<![\w$])onmessage\s*=(?!=)\s*''')
_POSTMESSAGE_RE = re.compile(r'''\.postMessage\s*\(\s*''')
_ORIGIN_STRICT_RE = re.compile(
    r'''\.origin\s*[!=]==?|[!=]==?\s*[\w$.]*\.origin\b|(?<![\w$.])origin\s*[!=]==?'''
    r'''|\.(?:includes|indexOf|has)\s*\(\s*[\w$.]*\.?origin\s*\)''')
_ORIGIN_WEAK_RE = re.compile(
    r'''\.origin\s*\.\s*(?:indexOf|includes|startsWith|endsWith|match|search|split|substr|substring|slice)\s*\('''
    r'''|(?:test|exec)\s*\(\s*[\w$.]*\.?origin\b''')

# ── functions (for handler resolution and one-level inter-procedural flow) ──
_FUNC_HEAD_RES = [
    # function NAME(params) {   /   function (params) {
    re.compile(r'''(?<![\w$.])(?:async\s+)?function\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)?\s*\((?P<params>[^()]{0,300})\)\s*\{'''),
    # NAME = function(params) {   /   NAME: function(params) {
    re.compile(r'''(?<![\w$])(?P<name>[A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?function\s*\*?\s*[\w$]*\s*\((?P<params>[^()]{0,300})\)\s*\{'''),
    # NAME = (params) => …   /   NAME = param => …
    re.compile(r'''(?<![\w$])(?P<name>[A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?(?:\((?P<params>[^()]{0,300})\)|(?P<p1>[A-Za-z_$][\w$]*))\s*=>\s*'''),
    # method shorthand: NAME(params) {   (keywords filtered below)
    re.compile(r'''(?<![\w$.])(?:async\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^()]{0,300})\)\s*\{'''),
]
_ANON_ARROW_RE = re.compile(r'''(?:async\s+)?(?:\((?P<params>[^()]{0,300})\)|(?P<p1>[A-Za-z_$][\w$]*))\s*=>\s*''')
_KEYWORDS = {"if", "for", "while", "switch", "catch", "with", "function", "return", "typeof", "new",
             "do", "else", "try", "finally", "await", "yield", "delete", "void", "in", "of", "case"}

# NAME = …  |  NAME += …  |  {a, b: c} = …  |  [a, b] = …
_ASSIGN_RE = re.compile(
    r'''(?<![\w$.])(?:(?:var|let|const)\s+)?(?:(?P<name>[A-Za-z_$][\w$]{0,60})|(?P<pattern>\{[^{}=;]{1,300}\}|\[[^\[\]=;]{1,300}\]))\s*(?P<op>\+?=)(?![=>])''')


def _param_names(params: str) -> list[str]:
    """Binding names in a parameter list, incl. destructured ones ({data, origin})."""
    names = []
    for p in split_top_level(params or "", ","):
        p = p.strip().lstrip(".")
        if not p:
            continue
        if p[0] in "{[":
            names += [n for n in IDENT_RE.findall(split_top_level(p, "=")[0]) if n not in _KEYWORDS]
        else:
            m = re.match(r"[A-Za-z_$][\w$]*", p)
            if m:
                names.append(m.group(0))
    return names


def _pattern_names(pattern: str) -> list[str]:
    """Targets of a destructuring pattern: {a, b: c, d = 1, ...e} → a, c, d, e."""
    names = []
    for part in split_top_level(pattern.strip()[1:-1], ","):
        part = split_top_level(part, "=")[0].strip().lstrip(".")
        if ":" in part:
            part = split_top_level(part, ":")[-1].strip()
        m = re.fullmatch(r"[A-Za-z_$][\w$]*", part)
        if m:
            names.append(m.group(0))
    return names


def _url_prefix(arg: str):
    """
    How a constant prefix constrains a URL built from tainted data:
      "fixed"    — "https://host/…" or a same-origin path: scheme and host fixed
      "redirect" — "//" or "https://" + tainted host: open redirect, no javascript:
      None       — tainted data controls the start of the URL
    """
    first = strip_parens(split_top_level(arg.strip())[0]) if arg.strip() else ""
    lit = None
    m = re.match(r'''^(["'])((?:(?!\1)[^\\]|\\.)*)\1$''', first)
    if m:
        lit = m.group(2)
    elif first.startswith("`"):
        lit = first[1:].split("${", 1)[0] if "${" in first else None
    if not lit:
        return None
    if re.match(r"(?i)https?://[^/?#\s]+[/?#]", lit) or re.match(r"^/(?!/)|^\./|^\.\./|^[\w.-]+/", lit):
        return "fixed"
    if re.match(r"(?i)^(?:https?:)?//", lit):
        return "redirect"
    if re.match(r"(?i)^javascript:", lit):
        return None
    return "fixed" if lit.startswith("?") or lit.startswith("#") else None


class _FileAnalysis:
    def __init__(self, text: str):
        self.text = text
        self.newlines = [m.start() for m in re.finditer("\n", text)]
        self.braces = brace_map(text)
        self.functions = []          # dicts: name, params, start, body_start, end
        self.handlers = []           # dicts: start, end, params, check
        self.findings = []

    # ── helpers ──────────────────────────────────────────────────────────────
    def line_of(self, pos):
        return bisect.bisect_left(self.newlines, pos) + 1

    def snippet_at(self, pos):
        line = self.line_of(pos)
        start = self.newlines[line - 2] + 1 if line >= 2 else 0
        end = self.newlines[line - 1] if line - 1 < len(self.newlines) else len(self.text)
        a, b = max(start, pos - 80), min(end, pos + 160)
        return ("…" if a > start else "") + self.text[a:b].strip() + ("…" if b < end else "")

    def body_span(self, after_pos):
        """Span of the body starting at after_pos: a {block} or an arrow expression."""
        i = after_pos
        while i < len(self.text) and self.text[i] in " \t\r\n":
            i += 1
        if i < len(self.text) and self.text[i] == "{":
            end = self.braces.get(i)
            return (i, end) if end is not None else None
        _, end = scan_js_expr_span(self.text, i, ARROW_BODY_LIMIT)
        return (i, end) if end > i else None

    # ── 1. functions & message handlers ──────────────────────────────────────
    def index_functions(self):
        seen, attempts = {}, 0
        for rx in _FUNC_HEAD_RES:
            for m in rx.finditer(self.text):
                attempts += 1
                if len(seen) >= MAX_FUNCTIONS or attempts > MAX_FUNCTIONS * 2:
                    break
                name = m.group("name") or ""
                if name in _KEYWORDS:
                    continue
                if rx is _FUNC_HEAD_RES[2]:
                    span = self.body_span(m.end())
                    params = m.group("params") if m.group("params") is not None else m.group("p1")
                else:
                    brace = m.end() - 1
                    end = self.braces.get(brace)
                    span = (brace, end) if end is not None else None
                    params = m.group("params")
                if not span:
                    continue
                prev = seen.get(span[0])
                if prev is None or (not prev["name"] and name):   # prefer the named head
                    seen[span[0]] = {"name": name, "params": _param_names(params), "start": m.start(),
                                     "body_start": span[0], "end": span[1]}
        self.functions = sorted(seen.values(), key=lambda f: f["start"])
        self.func_starts = [f["start"] for f in self.functions]

    def enclosing_function(self, pos):
        """Innermost indexed function whose body contains pos."""
        i = bisect.bisect_right(self.func_starts, pos) - 1
        best, steps = None, 0
        while i >= 0 and steps < 400:
            f = self.functions[i]
            if f["body_start"] <= pos <= f["end"]:
                if best is None or f["body_start"] > best["body_start"]:
                    best = f
                    break
            i -= 1
            steps += 1
        return best

    def index_handlers(self):
        by_name = {}
        for f in self.functions:
            if f["name"] and f["name"] not in by_name:
                by_name[f["name"]] = f
        for i, m in enumerate(_MSG_LISTEN_RE.finditer(self.text)):
            if i >= MAX_HANDLERS:
                break
            pos = m.end()
            head = self.text[pos:pos + 400]
            span, params = None, []
            fm = _FUNC_HEAD_RES[0].match(head)
            am = _ANON_ARROW_RE.match(head)
            if fm:
                brace = pos + fm.end() - 1
                end = self.braces.get(brace)
                span = (brace, end) if end is not None else None
                params = _param_names(fm.group("params"))
            elif am:
                span = self.body_span(pos + am.end())
                params = _param_names(am.group("params") if am.group("params") is not None else am.group("p1"))
            else:
                ref = re.match(r"[\w$.]+", head)
                target = by_name.get(ref.group(0).split(".")[-1]) if ref else None
                if target:
                    span, params = (target["body_start"], target["end"]), target["params"]
            if not span:
                self.add_finding("message handler (defined elsewhere)", "postmessage", "low", "low",
                                 None, m.start(), note="handler not resolved in this file — review it manually")
                continue
            body = self.text[span[0]:span[1] + 1]
            if _ORIGIN_STRICT_RE.search(body):
                check = "strict"
            elif _ORIGIN_WEAK_RE.search(body):
                check = "weak"
            else:
                check = "none"
            data_tokens = []
            if params:
                data_tokens.append(re.compile(r"(?<![\w$.])" + re.escape(params[0]) + r"\s*\.\s*data\b"))
                if "data" in params[1:] or (params and params[0] == "data"):
                    data_tokens.append(re.compile(r"(?<![\w$.])data(?![\w$])"))
            # destructured first param: ({data, origin}) => …
            if params and "data" in params:
                data_tokens.append(re.compile(r"(?<![\w$.])data(?![\w$])"))
            h = {"start": span[0], "end": span[1], "check": check, "tokens": data_tokens}
            self.handlers.append(h)
            uses_data = any(t.search(body) for t in data_tokens)
            if check == "none":
                self.add_finding("message handler without origin check", "postmessage", "high", "high",
                                 "message data" if uses_data else None, m.start(),
                                 note="any page that can frame or open this one can send it messages")
            elif check == "weak":
                self.add_finding("message handler with weak origin check", "postmessage", "medium", "medium",
                                 "message data" if uses_data else None, m.start(),
                                 note="origin compared with indexOf/includes/startsWith/regex — often bypassable "
                                      "with a look-alike domain; check the exact comparison")

    # ── 2. taint evaluation ──────────────────────────────────────────────────
    def _sanitized_spans(self, expr):
        spans = []
        for m in _SANITIZER_RE.finditer(expr):
            if len(spans) >= 20:
                break
            _, end = call_args_span(expr, m.end(), 1000)
            spans.append((m.start(), end))
        return spans

    def taint_of(self, expr, pos, tainted_vars):
        """
        Best taint reaching `expr` (at text position `pos`):
          {source, category, chain, sanitized, flow, via, origin_check}  or None
        """
        if not expr:
            return None
        spans = self._sanitized_spans(expr) if _SANITIZER_RE.search(expr) else []

        def inside(a):
            return any(s <= a < e for s, e in spans)

        cands = []
        # direct source in the expression (cheap keyword check, then one regex search)
        m = _ANY_SOURCE_RE.search(expr) if _may_have_source(expr) else None
        if m:
            label, cat, _ = _SOURCES[int(m.lastgroup[1:])]
            cands.append({"source": label, "category": cat, "chain": [], "sanitized": inside(m.start()),
                          "flow": "direct", "via": None})
        # postMessage data inside an enclosing handler
        for h in (self.handlers if "data" in expr else ()):
            if h["start"] <= pos <= h["end"]:
                for tok in h["tokens"]:
                    m = tok.search(expr)
                    if m:
                        cands.append({"source": "postMessage data", "category": "message", "chain": [],
                                      "sanitized": inside(m.start()) or h["check"] == "strict",
                                      "flow": "message data", "via": None, "origin_check": h["check"]})
                        break
        # tainted variables
        if tainted_vars:
            for m in IDENT_RE.finditer(expr):
                info = tainted_vars.get(m.group(0))
                if not info:
                    continue
                dist = SHORT_NAME_DISTANCE if len(m.group(0)) <= 2 else TAINT_DISTANCE
                if pos - info["pos"] > dist:
                    continue
                c = dict(info["taint"])
                c["sanitized"] = c["sanitized"] or inside(m.start())
                c["flow"] = c.get("flow") if c.get("flow") == "message data" else f"via variable '{m.group(0)}'"
                c["via"] = m.group(0)
                cands.append(c)
        if not cands:
            return None
        cands.sort(key=lambda c: (c["sanitized"], _CATEGORY_RANK.get(c["category"], 3), len(c["chain"])))
        return cands[0]

    # ── 3. findings ──────────────────────────────────────────────────────────
    def add_finding(self, sink, kind, severity, confidence, flow, pos, note=None, taint=None,
                    trace=None, sanitized=False):
        if len(self.findings) >= MAX_FINDINGS_PER_FILE:
            return None
        f = {"sink": sink, "kind": kind, "severity": severity, "confidence": confidence, "flow": flow,
             "line": self.line_of(pos), "snippet": self.snippet_at(pos), "sanitized": sanitized}
        if taint:
            f["source"] = taint["source"]
            f["source_category"] = taint["category"]
        if trace:
            f["trace"] = trace
            f["trace_text"] = " → ".join(f"{s['detail']} (L{s['line']})" for s in trace)
        if note:
            f["note"] = note
        self.findings.append(f)
        return f

    @staticmethod
    def severity(kind, taint, prefix):
        if taint is None:
            return {"code": "medium", "framework": "medium"}.get(kind, "low")
        if kind == "html-sanitized":
            return "low"
        if taint["sanitized"]:
            return "low"
        if kind in ("nav", "script-url", "nav-click") and prefix == "fixed":
            return "low"
        if kind == "nav-app":
            return "low"
        if prefix == "redirect" or kind in ("storage-write", "cookie-write", "nav-click"):
            return "medium"
        if taint.get("origin_check") == "weak":
            return "medium"
        if taint["category"] in _STORED:
            return "medium"
        return "high"

    def run(self):
        text = self.text
        self.index_functions()
        self.index_handlers()

        # sink events
        sink_events = []
        for label, kind, rx, mode, only in _SINK_RES:
            for m in rx.finditer(text):
                if len(sink_events) >= MAX_FINDINGS_PER_FILE * 4:
                    break
                if mode in ("rhs", "expr"):
                    arg, _ = scan_js_expr_span(text, m.end(), ARG_LIMIT)
                else:
                    args, _ = call_args_span(text, m.end(), ARG_LIMIT)
                    arg = ", ".join(args) if mode == "allargs" else (args[mode] if len(args) > mode else "")
                if is_constant_expr(arg):
                    continue
                k, lab = kind, label
                attr = m.groupdict().get("attr")
                if attr:
                    lab = f"setAttribute('{attr}')"
                    k = "code" if attr.startswith("on") else ("html" if attr == "srcdoc" else "nav")
                sink_events.append({"pos": m.start(), "label": lab, "kind": k, "arg": arg, "only": only})
        # sinks on elements created with document.createElement(...)
        elems = {}
        for m in _CREATE_EL_RE.finditer(text):
            elems.setdefault(m.group(1), m.group(2))
            if len(elems) >= 200:
                break
        if elems:
            el_re = re.compile(r'''(?<![\w$.])(''' + "|".join(re.escape(n) for n in elems)
                               + r''')\s*\.\s*(src|href|action|data)\s*=(?!=)\s*''')
            for m in el_re.finditer(text):
                kind = _ELEMENT_SINK_KIND.get((elems[m.group(1)], m.group(2)))
                if not kind:
                    continue
                arg, _ = scan_js_expr_span(text, m.end(), ARG_LIMIT)
                if not is_constant_expr(arg):
                    sink_events.append({"pos": m.start(), "label": f"<{elems[m.group(1)]}>.{m.group(2)}",
                                        "kind": kind, "arg": arg, "only": True})

        # function summaries: parameter → sink inside the same function
        # summaries[name][param_index] = [(param, sink_event, fn), …]  (capped)
        summaries = {}
        for ev in sink_events:
            fn = self.enclosing_function(ev["pos"])
            if not fn or len(fn["name"]) < 3:
                continue                      # 1–2 char names collide everywhere in minified code
            for i, p in enumerate(fn["params"]):
                if re.search(r"(?<![\w$.])" + re.escape(p) + r"(?![\w$])", ev["arg"]):
                    entries = summaries.setdefault(fn["name"], {}).setdefault(i, [])
                    if len(entries) < MAX_SINKS_PER_PARAM:
                        entries.append((p, ev, fn))
        call_events = []
        if summaries:
            call_re = re.compile(r"(?<![\w$])(" + "|".join(re.escape(n) for n in summaries) + r")\s*\(")
            for m in call_re.finditer(text):
                if len(call_events) >= MAX_CALL_SITES:
                    break
                before = text[max(0, m.start() - 16):m.start()]
                if re.search(r"function\s*\*?\s*$", before):
                    continue                                   # `function render(`
                if (re.match(r"\s*\([^()]{0,300}\)\s*\{", text[m.end() - 1:m.end() + 320])
                        and re.search(r"(?:^|[{};,]|\b(?:async|static|get|set))\s*$", before)):
                    continue                                   # method shorthand `render(x) {`
                args, _ = call_args_span(text, m.end(), ARG_LIMIT)
                call_events.append({"pos": m.start(), "name": m.group(1), "args": args})

        # assignment events
        assign_events = []
        for m in _ASSIGN_RE.finditer(text):
            if len(assign_events) >= MAX_ASSIGNMENTS:
                break
            rhs, _ = scan_js_expr_span(text, m.end(), RHS_LIMIT)
            names = [m.group("name")] if m.group("name") else _pattern_names(m.group("pattern"))
            names = [n for n in names if n not in _KEYWORDS]
            if names and rhs:
                assign_events.append({"pos": m.start(), "names": names, "op": m.group("op"), "rhs": rhs})

        # forward pass in source order
        events = ([("a", e["pos"], e) for e in assign_events] + [("s", e["pos"], e) for e in sink_events]
                  + [("c", e["pos"], e) for e in call_events])
        events.sort(key=lambda t: (t[1], {"a": 1, "s": 0, "c": 0}[t[0]]))
        tainted = {}
        sink_results = {}
        call_results = []
        for typ, pos, ev in events:
            if typ == "a":
                t = self.taint_of(ev["rhs"], pos, tainted)
                for n in ev["names"]:
                    if t:
                        chain = list(t["chain"])
                        if not chain:
                            chain = [{"step": "source", "detail": t["source"], "line": self.line_of(pos)}]
                        chain = chain + [{"step": "assign", "detail": n, "line": self.line_of(pos)}]
                        tainted[n] = {"pos": pos, "taint": {**t, "chain": chain}}
                    elif ev["op"] == "=" and n in tainted:
                        del tainted[n]                  # clean reassignment kills the taint
            elif typ == "s":
                sink_results[id(ev)] = (ev, self.taint_of(ev["arg"], pos, tainted))
            else:
                # one taint evaluation per argument, then attach to that parameter's sinks
                for i, entries in summaries.get(ev["name"], {}).items():
                    if i < len(ev["args"]):
                        t = self.taint_of(ev["args"][i], pos, tainted)
                        if t:
                            for p, sev, fn in entries:
                                call_results.append((ev, i, p, sev, fn, t))

        # sink findings
        upgraded = {}
        for ev, i, p, sev, fn, t in call_results:
            key = id(sev)
            if key not in upgraded or (upgraded[key][5]["sanitized"] and not t["sanitized"]):
                upgraded[key] = (ev, i, p, sev, fn, t)
        for key, (ev, taint) in sink_results.items():
            via_call = None
            if (taint is None or taint["sanitized"]) and key in upgraded:
                via_call = upgraded[key]
                taint = via_call[5]
            if ev["only"] and taint is None:
                continue
            prefix = _url_prefix(ev["arg"]) if ev["kind"] in ("nav", "script-url", "nav-click") else None
            severity = self.severity(ev["kind"], taint, prefix)
            note = None
            trace = None
            flow = None
            confidence = "low"
            if taint:
                # a direct source has no chain yet: it sits at the call site (via call) or the sink
                src_pos = via_call[0]["pos"] if via_call else ev["pos"]
                chain = list(taint["chain"]) or [{"step": "source", "detail": taint["source"],
                                                  "line": self.line_of(src_pos)}]
                if via_call:
                    call_ev, idx, pname, _, fn, _ = via_call
                    chain = chain + [{"step": "call", "detail": f"{fn['name']}() arg {idx + 1}",
                                      "line": self.line_of(call_ev["pos"])},
                                     {"step": "param", "detail": pname, "line": self.line_of(fn["start"])}]
                    flow = f"via call {fn['name']}()"
                    confidence = "medium"
                else:
                    flow = taint["flow"]
                    confidence = "high" if flow in ("direct", "message data") or len(taint["chain"]) <= 2 else "medium"
                trace = chain + [{"step": "sink", "detail": ev["label"], "line": self.line_of(ev["pos"])}]
                if taint["sanitized"]:
                    note = "passes through a sanitizer/encoder or a strict origin check — verify it fits this sink"
                elif prefix == "fixed":
                    note = "constant scheme/host prefix: javascript: URLs are not possible here"
                elif prefix == "redirect":
                    note = "tainted host after a constant // or https:// prefix: open redirect, not script execution"
                elif taint["category"] in _STORED:
                    note = "stored source: exploitable only if an attacker can write it first"
            elif ev["kind"] == "html-sanitized":
                note = "Angular sanitizes [innerHTML] bindings — risky only together with bypassSecurityTrust*"
            self.add_finding(ev["label"], ev["kind"], severity, confidence, flow, ev["pos"], note=note,
                             taint=taint, trace=trace, sanitized=bool(taint and taint["sanitized"]))

        # postMessage senders with targetOrigin "*"
        for i, m in enumerate(_POSTMESSAGE_RE.finditer(text)):
            if i >= 500:
                break
            args, _ = call_args_span(text, m.end(), ARG_LIMIT)
            if len(args) >= 2 and args[1].strip() in ('"*"', "'*'", "`*`"):
                self.add_finding('postMessage(…, "*")', "postmessage", "medium", "high", None, m.start(),
                                 note="message readable by whatever window is at the target — check what is sent")

        self.findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"]))
        return self.findings


def find_dom_issues(text: str) -> list[dict]:
    """
    Scan one file for DOM XSS sinks, sources and postMessage issues.
    Returns findings sorted by severity:
      {sink, kind, severity, confidence, flow, line, snippet, sanitized,
       source?, source_category?, trace?, trace_text?, note?}
    """
    return _FileAnalysis(text).run()


def find_dom_sources(text: str) -> list[dict]:
    """Every place a known source is read: [{source, category, line, snippet}]."""
    fa = _FileAnalysis.__new__(_FileAnalysis)
    fa.text = text
    fa.newlines = [m.start() for m in re.finditer("\n", text)]
    out = []
    for label, cat, rx in _SOURCE_RES:
        for m in rx.finditer(text):
            if len(out) >= MAX_SOURCES_PER_FILE:
                break
            out.append({"source": label, "category": cat, "line": fa.line_of(m.start()),
                        "snippet": fa.snippet_at(m.start())})
    return sorted(out, key=lambda s: s["line"])


def find_dom_issues_in_files(files: list[tuple[str, str, int]]) -> tuple[list[dict], list[dict]]:
    """
    Per-file analysis with real file:line locations (header_lines offset).
    The same sink often appears in a bundle and in its recovered original
    source, so findings are grouped by (sink, normalised snippet).
    Returns (findings, sources_inventory).
    """
    grouped, sources = {}, []
    for path, text, offset in files:
        for f in find_dom_issues(text):
            loc = {"file": path, "line": f["line"] + offset}
            key = (f["sink"], re.sub(r"\s+", "", f["snippet"]))
            if key not in grouped:
                g = {**f, **loc, "locations": []}
                if "trace" in g:
                    g["trace"] = [{**s, "line": s["line"] + offset} for s in g["trace"]]
                    g["trace_text"] = " → ".join(f"{s['detail']} (L{s['line']})" for s in g["trace"])
                grouped[key] = g
            grouped[key]["locations"].append(loc)
        for s in find_dom_sources(text):
            sources.append({**s, "file": path, "line": s["line"] + offset})
    findings = sorted(grouped.values(),
                      key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))
    return findings, sources
