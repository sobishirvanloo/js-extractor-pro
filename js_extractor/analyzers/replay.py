"""
Turn discovered endpoints + params + auth into replay-ready artefacts:
an OpenAPI 3.0 document, ready-to-run curl commands, and ffuf fuzzing lines.

This is what makes the recon actionable — instead of a flat endpoint list, you
get a spec you can import into Postman/Insomnia and commands you can paste into
a terminal or pipe into a fuzzer, already carrying the method and your auth.
"""
import re
from urllib.parse import urljoin, urlparse

_PLACEHOLDER = "https://TARGET"      # used when analysing local files (no real origin)
_PARAM_RE = re.compile(r"\{(\w+)\}")


def _origin(base_url: str) -> str:
    p = urlparse(base_url)
    if p.scheme in ("http", "https") and p.hostname:
        return f"{p.scheme}://{p.netloc}"
    return _PLACEHOLDER


def _absolute(path: str, origin: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    return urljoin(origin + "/", path.lstrip("/"))


def _split(path: str, origin: str) -> tuple[str, str]:
    """Return (server_origin, path_only) for an endpoint."""
    if path.startswith(("http://", "https://")):
        u = urlparse(path)
        return f"{u.scheme}://{u.netloc}", (u.path or "/")
    return origin, "/" + path.lstrip("/")


def build_openapi(endpoint_details: list[dict], params: list[str], base_url: str,
                  title: str = "Recovered API") -> dict:
    """Synthesize a minimal OpenAPI 3.0 document from the endpoint list.
    Path templates like /users/{param} become path parameters; the full list
    of discovered parameter names is preserved under x-discovered-params."""
    origin = _origin(base_url)
    servers, paths = {}, {}
    for d in endpoint_details:
        server, path = _split(d["path"], origin)
        servers[server] = True
        # OpenAPI path templating: {param} stays; bare colons/regex are dropped
        tmpl = path
        path_params = _PARAM_RE.findall(tmpl)
        methods = d.get("methods") or ["GET"]
        op = paths.setdefault(tmpl, {})
        for method in methods:
            entry = {
                "summary": ("hidden/internal endpoint" if d.get("hidden") else "discovered endpoint"),
                "responses": {"default": {"description": "unknown (statically discovered)"}},
            }
            if d.get("hidden"):
                entry["x-hidden"] = True
            if d.get("file"):
                entry["x-source"] = f"{d['file']}:{d.get('line', '?')}"
            if path_params:
                entry["parameters"] = [
                    {"name": pp, "in": "path", "required": True, "schema": {"type": "string"}}
                    for pp in dict.fromkeys(path_params)
                ]
            op[method.lower()] = entry

    doc = {
        "openapi": "3.0.3",
        "info": {"title": title, "version": "0.0.0",
                 "description": "Statically reconstructed from client JS by js-extractor. "
                                "Unverified: endpoints/methods are inferred, not confirmed."},
        "servers": [{"url": s} for s in servers],
        "paths": paths,
    }
    if params:
        doc["x-discovered-params"] = sorted(params)
    return doc


def build_curl_commands(endpoint_details: list[dict], base_url: str,
                        headers: dict | None = None, cookie: str = "") -> list[str]:
    """One runnable curl per (endpoint, method), carrying the supplied auth."""
    origin = _origin(base_url)
    headers = headers or {}
    hdr_flags = "".join(f" -H {_shq(f'{k}: {v}')}" for k, v in headers.items())
    cookie_flag = f" -b {_shq(cookie)}" if cookie else ""
    lines = []
    for d in endpoint_details:
        url = _absolute(d["path"], origin)
        for method in (d.get("methods") or ["GET"]):
            tag = "  # hidden/internal" if d.get("hidden") else ""
            body = " -H 'Content-Type: application/json' -d '{}'" if method in ("POST", "PUT", "PATCH") else ""
            lines.append(f"curl -sS -k -X {method}{hdr_flags}{cookie_flag}{body} {_shq(url)}{tag}")
    return lines


def build_ffuf_commands(endpoint_details: list[dict], base_url: str,
                        params_wordlist: str = "params_wordlist.txt") -> list[str]:
    """Example ffuf lines: parameter fuzzing on GET endpoints, plus a note on
    path discovery. Illustrative — the tester adjusts matchers/filters."""
    origin = _origin(base_url)
    cmds = []
    gets = [d for d in endpoint_details
            if ("GET" in (d.get("methods") or ["GET"])) and "{" not in d["path"]]
    for d in gets[:25]:
        url = _absolute(d["path"], origin)
        sep = "&" if urlparse(url).query else "?"
        cmds.append(f"ffuf -w {params_wordlist}:FUZZ -u {_shq(url + sep + 'FUZZ=ffuf')} "
                    f"-mc all -ac")
    return cmds


def _shq(s: str) -> str:
    """Single-quote a string for a POSIX shell."""
    return "'" + s.replace("'", "'\\''") + "'"
