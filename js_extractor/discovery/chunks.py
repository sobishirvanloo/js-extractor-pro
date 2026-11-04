"""
Lazy chunk discovery: webpack runtime chunk-URL templates, Next.js build manifests,
Vite preload lists and manifests.
"""
import json
import re
from urllib.parse import urljoin

from ..jsparse import scan_js_expr, split_top_level, strip_parens
from ..net import resolve


_JS_OBJ_ENTRY_RE = re.compile(
    r'''(?:(\d+)|"([^"]*)"|'([^']*)'|([A-Za-z_$][\w$]*))\s*:\s*(?:"([^"]*)"|'([^']*)')''')



def _parse_js_map(obj: str) -> dict:
    """Parse a flat {key: "string"} object literal as emitted by webpack."""
    out = {}
    for m in _JS_OBJ_ENTRY_RE.finditer(obj):
        key = next(g for g in m.groups()[:4] if g is not None)
        out[key] = m.group(5) if m.group(5) is not None else m.group(6)
    return out



class ChunkTemplate:
    """
    A webpack chunk-URL function compiled to a list of parts:
      ("lit", s) | ("id",) | ("p",) | ("map", {id: s}, fallback_to_id)
    """

    def __init__(self, parts, public_path, has_p, script_url, fixed=None):
        self.parts, self.public_path, self.has_p, self.script_url = parts, public_path, has_p, script_url
        self.fixed = fixed or {}        # id -> literal path, from `ID===e?"path":...` ternaries

    @property
    def known_ids(self) -> set:
        """Ids enumerated by a map without fallback (the contenthash map lists every chunk)."""
        ids = set(self.fixed)
        for p in self.parts:
            if p[0] == "map" and not p[2]:
                ids |= set(p[1])
        return ids

    def _absolute(self, path: str, page_url: str, prefixed: bool):
        if not prefixed:
            path = (self.public_path or "") + path
        # publicPath "" (webpack 4 default) is relative to the page; an
        # unknown/"auto" publicPath (webpack 5) is relative to the runtime script
        base = page_url if self.public_path == "" else self.script_url
        return resolve(path, base)

    def url_for(self, chunk_id: str, page_url: str):
        if chunk_id in self.fixed:
            return self._absolute(self.fixed[chunk_id], page_url, False)
        out = []
        for p in self.parts:
            if p[0] == "lit":
                out.append(p[1])
            elif p[0] == "id":
                out.append(chunk_id)
            elif p[0] == "p":
                out.append(self.public_path or "")
            else:                                   # map lookup
                val = p[1].get(chunk_id)
                if val is None:
                    if not p[2]:
                        return None                 # no hash for this id → not a chunk
                    val = chunk_id
                out.append(val)
        return self._absolute("".join(out), page_url, self.has_p)



_CHUNK_FN_RES = [
    # webpack 5:  r.u = e => "static/js/" + e + ".js"   |   r.u = function(e){ return ... }
    # (minifiers drop the space: `return"static/js/"+e`)
    # The (?<![\w$]) anchor matters: without it `[\w$]+` is retried from every
    # position inside long identifiers/strings → O(n²) on multi-MB bundles.
    re.compile(r'''(?<![\w$])([\w$]{1,64})\.u\s*=\s*(?:function\s*\(\s*([\w$]+)\s*\)\s*\{\s*return(?![\w$])\s*'''
               r'''|\(?\s*([\w$]+)\s*\)?\s*=>\s*(?:\{\s*return(?![\w$])\s*|\(?))'''),
    # webpack 4:  function jsonpScriptSrc(chunkId) { return __webpack_require__.p + ... }
    re.compile(r'''function\s+jsonpScriptSrc\s*\(\s*([\w$]+)\s*\)\s*\{\s*return(?![\w$])\s*()'''),
]



_CHUNK_ID_RE = re.compile(r'''(?<![\w$])[\w$]{1,40}\.e\(\s*(\d+|"[^"\\]{1,200}"|'[^'\\]{1,200}')\s*\)''')



MAX_CHUNK_FN_CANDIDATES = 10     # a real bundle has 1-2 runtimes; bounds hostile input



def find_chunk_templates(js_code: str, script_url: str) -> list[ChunkTemplate]:
    """Compile every webpack chunk-URL function found in this script."""
    templates, tried, public_paths = [], 0, {}
    for rx in _CHUNK_FN_RES:
        for m in rx.finditer(js_code):
            tried += 1
            if tried > MAX_CHUNK_FN_CANDIDATES:
                return templates
            if rx is _CHUNK_FN_RES[0]:
                obj, param = m.group(1), m.group(2) or m.group(3)
            else:
                obj, param = "__webpack_require__", m.group(1)
            if not param:
                continue
            # Ternary chains need the whole `a ? b : c` — scan with ':' and '?'
            # allowed, then peel off `ID===e?"literal":` (or `e===ID?...`) prefixes.
            expr = scan_js_expr(js_code, m.end())
            fixed, p = {}, re.escape(param)
            tern = re.compile(r'''\s*(?:(\d+|"[^"]*"|'[^']*')\s*===?\s*''' + p + r'''|''' + p
                              + r'''\s*===?\s*(\d+|"[^"]*"|'[^']*'))\s*\?\s*("[^"]*"|'[^']*')\s*:\s*''')
            while True:
                t = tern.match(expr)
                if not t:
                    break
                fixed[(t.group(1) or t.group(2)).strip("\"'")] = t.group(3)[1:-1]
                expr = expr[t.end():]
            parts, has_p = [], False
            for term in split_top_level(expr):
                term = strip_parens(term)
                lit = re.fullmatch(r'''"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)\'''', term)
                if lit:
                    parts.append(("lit", lit.group(1) if lit.group(1) is not None else lit.group(2)))
                elif term == param:
                    parts.append(("id",))
                elif re.fullmatch(r"[\w$]+\.p", term):
                    parts.append(("p",)); has_p = True
                else:
                    lk = re.fullmatch(r"\(?\s*(\{.*\})\s*\)?\s*\[\s*" + re.escape(param)
                                      + r"\s*\]\s*(\|\|\s*" + re.escape(param) + r")?", term, re.S)
                    if not lk:
                        parts = None
                        break                       # unsupported construct — skip this fn
                    parts.append(("map", _parse_js_map(lk.group(1)), bool(lk.group(2))))
            if not parts or not any(p[0] == "lit" and re.search(r"\.m?js(\?|$)", p[1]) for p in parts):
                continue                            # not a JS chunk-URL builder
            # Public path: `<obj>.p = "..."` in the same runtime (one scan per object name)
            if obj not in public_paths:
                pm = re.search(r'(?<![\w$])' + re.escape(obj) + r'''\.p\s*=\s*(["'])([^"'\n]{0,500})\1''', js_code)
                public_paths[obj] = pm.group(2) if pm else None
            public_path = public_paths[obj]
            templates.append(ChunkTemplate(parts, public_path, has_p, script_url, fixed))
    return templates



def find_chunk_ids(js_code: str) -> set:
    """Chunk ids from `__webpack_require__.e(id)` calls (`n.e(42)` minified)."""
    return {m.group(1).strip("\"'") for m in _CHUNK_ID_RE.finditer(js_code)}



# Vite preload deps / generic bundler asset paths: "assets/About-1a2b3c.js"
_ASSET_PATH_RE = re.compile(
    r'''["'`]((?:\.?/)?(?:[\w\-.]+/)*(?:assets|chunks|static/js|static/chunks|js|dist|build)/'''
    r'''[\w\-.~/@]+?\.m?js)["'`]''')



def find_asset_paths(js_code: str, script_url: str, page_url: str) -> list[str]:
    """
    Script paths that bundlers keep as plain strings (Vite's __vitePreload
    dependency arrays, chunk lists). Bare "assets/x.js" is relative to the
    site base (Vite default base "/"); "./x.js" to the script itself.
    """
    out = []
    origin_root = urljoin(page_url, "/")
    for m in _ASSET_PATH_RE.finditer(js_code):
        p = m.group(1)
        base = script_url if p.startswith("./") else origin_root
        url = resolve(p, base)
        if url:
            out.append(url)
    return out



def parse_next_build_manifest(js_code: str, manifest_url: str) -> tuple[list[str], list[str]]:
    """
    Next.js _buildManifest.js → (chunk URLs, page routes). Chunk paths are
    relative to the asset prefix, i.e. everything before "/static/" in the
    manifest URL (".../_next/").
    """
    if "__BUILD_MANIFEST" not in js_code:
        return [], []
    prefix = manifest_url.split("/static/")[0] + "/"
    chunks = [urljoin(prefix, p) for p in re.findall(r'''["'](static/[^"']+?\.js)["']''', js_code)]
    routes = sorted(set(re.findall(r'''["'](/[^"']*)["']\s*:\s*\[''', js_code)))
    return list(dict.fromkeys(chunks)), routes



def next_build_manifest_urls(html: str, script_urls: list[str], page_url: str) -> list[str]:
    """Candidate _buildManifest.js URLs from the buildId in __NEXT_DATA__ / script paths."""
    ids = set(re.findall(r'''"buildId"\s*:\s*"([\w\-]+)"''', html))
    prefix = urljoin(page_url, "/_next/")
    for u in script_urls:
        m = re.search(r"^(.*?/_next/)static/([\w\-]+)/_(?:build|ssg)Manifest\.js", u)
        if m:
            ids.add(m.group(2)); prefix = m.group(1)
        elif "/_next/static/" in u:
            prefix = u.split("/_next/static/")[0] + "/_next/"
    return [f"{prefix}static/{i}/_buildManifest.js" for i in sorted(ids)]



def parse_vite_manifest(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Vite manifest.json → (chunk URLs, original source paths)."""
    try:
        data = json.loads(text)
    except ValueError:
        return [], []
    if not isinstance(data, dict):
        return [], []
    files, sources = [], []
    for src, entry in data.items():
        if isinstance(entry, dict) and isinstance(entry.get("file"), str):
            sources.append(src)
            if re.search(r"\.m?js$", entry["file"]):
                files.append(urljoin(base_url, entry["file"]))
    return files, sources

