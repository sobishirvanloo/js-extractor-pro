"""
Beautifying and writing scripts and machine-readable results to disk.
"""
import json
import re
from pathlib import Path

import jsbeautifier

from .ui import green


# jsbeautifier is a pure-Python reformatter: on a multi-megabyte bundle it can
# take minutes (and a lot of RAM). Above this many bytes we skip the full
# reformat and do a cheap newline split instead — enough to make regex analysis
# line-aware without stalling the run. Tunable via --max-beautify-size.
DEFAULT_MAX_BEAUTIFY_BYTES = 2_000_000

# Split after statement/block boundaries, but only when they're followed by a
# non-newline — a fast approximation of beautify for oversized files.
_LIGHT_SPLIT = re.compile(r'([;{}])(?=\S)')


def light_prettify(js_code: str) -> str:
    """Cheap line-splitter for files too big to fully beautify. Best-effort:
    it can split inside a string literal, so it's only used past the size cap
    where a full reformat would be prohibitively slow."""
    return ("/* note: file exceeded beautify size cap — lightly prettified "
            "(line splits are approximate) */\n") + _LIGHT_SPLIT.sub(r"\1\n", js_code)


def beautify(js_code: str, max_bytes: int = DEFAULT_MAX_BEAUTIFY_BYTES) -> str:
    """Prettify minified JavaScript with js-beautifier.

    Files larger than ``max_bytes`` (0 disables the cap) get the cheap
    ``light_prettify`` treatment instead, so one giant bundle can't hang the
    whole run."""
    if max_bytes and len(js_code) > max_bytes:
        return light_prettify(js_code)
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

