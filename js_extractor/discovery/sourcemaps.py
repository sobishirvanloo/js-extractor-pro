"""
Source map discovery, parsing and safe recovery of original sources.
"""
import base64
import json
import re
import urllib.parse
from pathlib import Path

import requests

from ..net import fetch, resolve, safe_filename
from ..ui import cyan, green, yellow


_SOURCEMAP_REF_RE = re.compile(
    r'(?://|/\*)[#@]\s*sourceMappingURL=([^\s*]+)', re.MULTILINE
)



def safe_sourcemap_dest(src_file: str, sm_root: Path):
    """
    Map an attacker-controlled `sources` entry from a source map to a path
    strictly inside sm_root. Drops '', '.', '..' segments (both / and \\
    separators), sanitises each remaining segment, then verifies the resolved
    path is still under sm_root. Returns None if no safe path can be built.
    """
    parts = [p for p in re.split(r"[\\/]+", src_file) if p not in ("", ".", "..")]
    parts = [re.sub(r"[^\w.\-]", "_", p) for p in parts]
    parts = [p for p in parts if p.strip(".")]   # no segments made only of dots
    if not parts:
        return None
    dest = (sm_root / Path(*parts)).resolve()
    if dest == sm_root or not dest.is_relative_to(sm_root):
        return None
    return dest



def _decode_data_uri(uri: str):
    """Decode a data: URI (base64 or percent-encoded). Returns text or None."""
    try:
        meta, payload = uri[5:].split(",", 1)
        if meta.lower().endswith(";base64"):
            return base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", "replace")
        return urllib.parse.unquote(payload)
    except Exception:
        return None



def parse_sourcemap(map_text: str) -> list[tuple[str, object]]:
    """
    Parse a Source Map v3 document with the stdlib json module.

    Handles the XSSI prefix ( )]}' ), `sourceRoot`, and index maps
    (`sections`, recursively). Returns a list of (source_path, content)
    pairs — content is None when the map lists a source without embedding
    its `sourcesContent`.
    """
    text = map_text.lstrip("﻿")
    if text.startswith(")]}"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    data = json.loads(text)

    def walk(sm: dict, depth: int = 0) -> list:
        if not isinstance(sm, dict) or depth > 5:
            return []
        if isinstance(sm.get("sections"), list):
            out = []
            for sec in sm["sections"]:
                if isinstance(sec, dict) and isinstance(sec.get("map"), dict):
                    out += walk(sec["map"], depth + 1)
            return out
        sources = sm.get("sources") or []
        contents = sm.get("sourcesContent") or []
        root = sm.get("sourceRoot") or ""
        if not isinstance(root, str):
            root = ""
        out = []
        for i, src in enumerate(sources):
            if not isinstance(src, str):
                continue
            content = contents[i] if i < len(contents) else None
            if root and "://" not in src and not src.startswith("/"):
                src = root.rstrip("/") + "/" + src
            out.append((src, content if isinstance(content, str) else None))
        return out

    return walk(data)



def find_sourcemap_ref(js_code: str, headers=None):
    """
    Locate the source map reference for a script: the LAST sourceMappingURL
    comment (bundlers append it at the end; earlier ones may belong to
    concatenated files), else the SourceMap / X-SourceMap response header.
    """
    matches = _SOURCEMAP_REF_RE.findall(js_code)
    if matches:
        return matches[-1].strip()
    if headers:
        for h in ("SourceMap", "X-SourceMap"):
            if headers.get(h):
                return headers[h].strip()
    return None



# Third-party code inside recovered sources. Kept for retire.js / version
# fingerprinting (that's where vulnerable libs live) but excluded from
# endpoint / param / secret / semgrep / LinkFinder passes, where it is noise.
VENDOR_DIR_NAMES = ("node_modules", "bower_components", "jspm_packages")



# Text source types worth analysing among recovered files
SOURCE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".vue", ".svelte", ".html", ".htm", ".json", ".graphql", ".gql",
}



def is_vendor_path(path: Path, root: Path) -> bool:
    """True if `path` sits under a vendor dir (checked relative to root only)."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(p in VENDOR_DIR_NAMES for p in parts)



def analysis_dirs(output_dir: Path) -> list[Path]:
    """Every output folder holding code worth scanning with external tools."""
    dirs = [output_dir / "external", output_dir / "inline", output_dir / "sourcemap_recovered",
            output_dir / "local"]       # "local" only exists under --input-dir
    return [d for d in dirs if d.is_dir() and any(d.iterdir())]



def read_recovered_sources(paths: list[Path], sm_root: Path) -> tuple[list, str, int]:
    """
    Read source-map-recovered files written during this run.
    Returns (first_party_files, vendor_text, n_vendor) where
    first_party_files is a list of (path, text).
    """
    app, vendor = [], []
    for p in paths:
        if p.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if is_vendor_path(p, sm_root):
            vendor.append(text)
        else:
            app.append((p, text))
    return app, "\n".join(vendor), len(vendor)



def try_recover_sourcemap(js_code: str, js_url: str, session: requests.Session, out_dir: Path,
                          headers=None, guess: bool = True, written: list = None,
                          rewrite_url=None) -> int:
    """
    Recover original (pre-bundle) sources for one script.

    The map is located via the sourceMappingURL comment, the SourceMap /
    X-SourceMap header, or — if neither exists and guess=True — by trying
    <script URL>.map (production sites often strip the comment but leave the
    .map file deployed).

    Output for each script goes to its own folder so same-named sources from
    different bundles don't overwrite each other:
      sourcemap_recovered/<bundle>/<original/path/...>
      sourcemap_recovered/<bundle>/_sources.txt   (every path listed in the
                                                   map, even without content)
    Returns the number of source files written.
    """
    map_ref = find_sourcemap_ref(js_code, headers)
    guessed = False

    if map_ref and map_ref.startswith("data:"):
        map_text = _decode_data_uri(map_ref)
        map_origin = "inline data: URI"
        if map_text is None:
            print(f"    {yellow('[WARN]')} Could not decode inline source map in {js_url}")
            return 0
    else:
        if map_ref:
            map_url = resolve(map_ref, js_url)
        elif guess:
            map_url = js_url.split("#", 1)[0].split("?", 1)[0] + ".map"
            guessed = True
        else:
            return 0
        if not map_url:
            return 0
        if not guessed:
            print(f"    {cyan('[SourceMap]')} Fetching: {map_url}")
        # rewrite_url: the map is resolved against the script's ORIGINAL URL,
        # then mapped to where it can be fetched (e.g. its Wayback snapshot)
        resp = fetch(rewrite_url(map_url) if rewrite_url else map_url, session, quiet=guessed)
        if not resp:
            return 0
        map_text = resp.text
        map_origin = map_url

    try:
        entries = parse_sourcemap(map_text)
    except (ValueError, TypeError, AttributeError) as e:
        # A guessed URL hitting a soft-404 HTML page is expected — stay quiet
        if not guessed:
            print(f"    {yellow('[WARN]')} Could not parse source map {map_origin}: {e}")
        return 0
    if not entries:
        return 0
    if guessed:
        print(f"    {cyan('[SourceMap]')} Found undeclared map: {map_origin}")

    bundle_name = safe_filename(js_url, prefix="map")[:-len(".js")]
    bundle_dir = out_dir / "sourcemap_recovered" / bundle_name
    bundle_dir.mkdir(parents=True, exist_ok=True)
    bundle_root = bundle_dir.resolve()

    recovered, unsafe = 0, 0
    index_lines = [f"# script: {js_url}", f"# map:    {map_origin}", ""]
    for src_file, content in entries:
        dest = safe_sourcemap_dest(src_file, bundle_root)
        if dest is None:
            unsafe += 1
            index_lines.append(f"[unsafe-skipped] {src_file}")
            continue
        if content is None:
            index_lines.append(f"[no-content]     {src_file}")
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Original sources are already readable and may be .ts/.vue/.css,
            # so they're written as-is rather than run through the JS beautifier.
            dest.write_text(content, encoding="utf-8")
        except OSError as e:
            index_lines.append(f"[write-error]    {src_file}  ({e})")
            continue
        recovered += 1
        if written is not None:
            written.append(dest)
        index_lines.append(f"{dest.relative_to(bundle_root)}  <-  {src_file}")

    (bundle_dir / "_sources.txt").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    no_content = len(entries) - recovered - unsafe
    msg = f"Recovered {recovered}/{len(entries)} source file(s) → {bundle_dir}"
    if no_content:
        msg += f"  ({no_content} listed without content)"
    print(f"    {green('[SourceMap]')} {msg}")
    if unsafe:
        print(f"    {yellow('[WARN]')} Skipped {unsafe} source path(s) that tried to escape the output dir")
    return recovered

