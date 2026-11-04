"""
Script references inside JS: import/require/import() chains and Web/Service Workers.
"""
import re

from ..net import resolve


# Matches: import x from './chunk.js' | import x from "/assets/a.js" |
#          require('../util.js') | import('./lazy.mjs') | export * from './b.js'
_IMPORT_RE = re.compile(
    r'''(?:import\s+[^;'"`]*?from\s*|export\s+[^;'"`]*?from\s*|import\s+|require\s*\(\s*|import\s*\(\s*)'''
    r'''['"`]((?:\.{1,2})?/[^'"`\s]+\.m?js(?:\?[^'"`\s]*)?)['"`]''',
    re.MULTILINE,
)



def find_js_imports(js_code: str, base_url: str) -> list[str]:
    """Extract relative JS import/require paths and resolve them against base_url."""
    found = []
    for m in _IMPORT_RE.finditer(js_code):
        resolved = resolve(m.group(1), base_url)
        if resolved:
            found.append(resolved)
    return found



_WORKER_RE = re.compile(
    r'''new\s+Worker\s*\(\s*['"`]([^'"`\s]+\.js[^'"`\s]*)['"`]'''
    r'''|navigator\.serviceWorker\.register\s*\(\s*['"`]([^'"`\s]+\.js[^'"`\s]*)['"`]''',
    re.MULTILINE,
)



def find_workers(js_code: str, base_url: str) -> list[str]:
    """Find Web Worker and Service Worker script URLs in JS source."""
    found = []
    for m in _WORKER_RE.finditer(js_code):
        src = m.group(1) or m.group(2)
        resolved = resolve(src, base_url)
        if resolved:
            found.append(resolved)
    return found

