"""
Beautifying and writing scripts and machine-readable results to disk.
"""
import json
from pathlib import Path

import jsbeautifier

from .ui import green


def beautify(js_code: str) -> str:
    """Prettify minified JavaScript with js-beautifier."""
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 2
    opts.wrap_line_length = 0
    opts.space_before_conditional = True
    opts.unescape_strings = True   # decode \\uXXXX and \\xXX sequences
    opts.jslint_happy = False
    opts.end_with_newline = True
    try:
        return jsbeautifier.beautify(js_code, opts)
    except Exception as e:
        return f"/* beautifier error: {e} */\n" + js_code



def save_js(content: str, path: Path, url: str = "") -> int:
    """
    Write beautified JS to disk with an optional source comment header.
    Returns how many lines the header adds, so line numbers computed on
    `content` can be mapped to the file on disk.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    header = f"/* Source: {url.replace('*/', '*_/')} */\n\n" if url else ""
    path.write_text(header + content, encoding="utf-8")
    print(f"  {green('[OK]')} Saved -> {path.name}")
    return header.count("\n")



def write_results(path: Path, results: dict, stream=None):
    """Write results.json and, with --json, the same document to `stream`."""
    doc = json.dumps(results, indent=2, ensure_ascii=False, default=str)
    path.write_text(doc + "\n", encoding="utf-8")
    if stream is not None:
        stream.write(doc + "\n")
        stream.flush()

