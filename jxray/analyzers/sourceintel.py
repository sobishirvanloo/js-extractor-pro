"""
Source intelligence from (recovered) first-party code.

When source maps are recovered the original project shows through: the import
graph, the directory tree, developer comments and contact emails. From the
import graph we also derive a dependency-confusion check — internal package
names (especially scoped `@company/*`) that are NOT published on the public npm
registry can often be claimed by an attacker and pulled into a build.
"""
import bisect
import re
import time

import requests

# Package specifiers reached by the three module systems.
_IMPORT_RES = (
    re.compile(r'''(?<![\w.])import\s+[^'"();]*?\sfrom\s+['"]([^'"]+)['"]'''),
    re.compile(r'''(?<![\w.])import\s+['"]([^'"]+)['"]'''),
    re.compile(r'''(?<![\w.$])require\s*\(\s*['"]([^'"]+)['"]\s*\)'''),
    re.compile(r'''(?<![\w.$])import\s*\(\s*['"]([^'"]+)['"]\s*\)'''),
    re.compile(r'''(?<![\w.])export\s+[^'"();]*?\sfrom\s+['"]([^'"]+)['"]'''),
)
_NODE_MODULES_RE = re.compile(r'node_modules/((?:@[\w.-]+/)?[\w.-]+)')
_EMAIL_RE = re.compile(r'(?<![\w.])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})')
_TODO_RE = re.compile(r'(?://|/\*|\*|#)\s*(TODO|FIXME|HACK|XXX|BUG|NOTE)\b[:\s]+(.{3,160})', re.I)

# Node builtins and tooling that 404 on npm but aren't "claimable".
_BUILTINS = {
    "fs", "path", "http", "https", "crypto", "os", "util", "stream", "events", "url",
    "querystring", "zlib", "buffer", "child_process", "net", "tls", "dns", "assert",
    "process", "module", "cluster", "readline", "vm", "worker_threads", "perf_hooks",
}
# Email domains that are placeholders / libraries, not real contacts.
_EMAIL_DENY = ("example.com", "example.org", "example.net", "sentry.io", "w3.org",
               "schema.org", "googleapis.com", "email.com", "domain.com", "test.com")

MAX_HITS = 5000


def _pkg_name(spec: str) -> str | None:
    """Normalise an import specifier to its npm package name, or None if it's a
    relative path, URL, data URI or Node builtin."""
    if not spec or spec[0] in "./" or "://" in spec or spec.startswith(("data:", "node:")):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    name = spec.split("/")[0]
    return None if name in _BUILTINS else name


def find_source_intel(files: list[tuple[str, str, int]], source_paths: list[str] | None = None) -> dict:
    """
    Gather packages / emails / TODO-comments from file contents, and the
    first-party file tree + vendored packages from source-map `sources` paths.

    Returns {packages, emails, todos, tree, tree_count}.
    """
    packages, emails, todos, tree = set(), set(), [], set()
    n = 0
    for path, text, offset in files:
        newlines = [i for i, ch in enumerate(text) if ch == "\n"]
        line_at = lambda pos: bisect.bisect_left(newlines, pos) + 1
        for rx in _IMPORT_RES:
            for m in rx.finditer(text):
                pkg = _pkg_name(m.group(1))
                if pkg:
                    packages.add(pkg)
        for m in _EMAIL_RE.finditer(text):
            addr = m.group(1)
            if not addr.lower().endswith(_EMAIL_DENY) and not addr.endswith((".png", ".svg", ".js")):
                emails.add(addr)
        for m in _TODO_RE.finditer(text):
            if n < MAX_HITS:
                n += 1
                todos.append({"file": path, "line": line_at(m.start()) + offset,
                              "tag": m.group(1).upper(), "text": m.group(2).strip()[:160]})

    for sp in source_paths or []:
        mods = _NODE_MODULES_RE.findall(sp)
        for mod in mods:
            pkg = _pkg_name(mod)
            if pkg:
                packages.add(pkg)
        if "node_modules" not in sp:
            clean = re.sub(r'^\w+:/{0,3}', "", sp).lstrip("./")      # strip webpack:/// etc.
            if clean and not clean.startswith(("<", "(")):
                tree.add(clean)

    return {
        "packages": sorted(packages),
        "emails": sorted(emails),
        "todos": todos,
        "tree": sorted(tree)[:1000],
        "tree_count": len(tree),
    }


# ── Dependency-confusion check against the public npm registry ────────────────
_NPM_REGISTRY = "https://registry.npmjs.org/"


def check_npm_packages(names: list[str], timeout: int = 10, limit: int = 200) -> list[dict]:
    """
    For each package name, ask the public npm registry whether it exists.
    404 → not published → a dependency-confusion candidate (high risk when the
    name is scoped `@org/pkg`, since the org prefix implies it's meant to be
    private). Returns [{name, scoped, status, risk}].
    status ∈ public | claimable | http_NNN | error.
    """
    out = []
    for name in sorted(names)[:limit]:
        enc = "@" + name[1:].replace("/", "%2f") if name.startswith("@") else name
        try:
            resp = requests.get(_NPM_REGISTRY + enc, timeout=timeout)
            code = resp.status_code
        except requests.exceptions.RequestException as e:
            out.append({"name": name, "scoped": name.startswith("@"), "status": "error",
                        "risk": "unknown", "detail": str(e)[:80]})
            continue
        if code == 200:
            status, risk = "public", "none"
        elif code == 404:
            status = "claimable"
            risk = "high" if name.startswith("@") else "medium"
        else:
            status, risk = f"http_{code}", "unknown"
        out.append({"name": name, "scoped": name.startswith("@"), "status": status, "risk": risk})
        time.sleep(0.05)       # polite pacing
    return out
