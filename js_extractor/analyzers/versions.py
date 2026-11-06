"""
Library version fingerprinting and CVE lookup via OSV.dev.
"""
import math
import re
import sys
import time

import requests

from ..ui import yellow


# (regex, npm_package_name) — matched against banner comments and filenames
# that ship inside the unminified/beautified JS. Ordered roughly by how
# commonly each library appears in the wild.
_LIB_VERSION_PATTERNS = [
    (r'jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)', "jquery"),
    (r'jquery[.\-]?(\d+\.\d+\.\d+)(?:\.min)?\.js', "jquery"),
    (r'jquery-ui[.\-]?(\d+\.\d+\.\d+)', "jquery-ui"),
    (r'AngularJS\s+v?(\d+\.\d+\.\d+)', "angular"),
    (r'angular[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "angular"),
    (r'@angular/core["\']?\s*[:=]\s*["\']?\^?(\d+\.\d+\.\d+)', "@angular/core"),
    (r'React\s+v?(\d+\.\d+\.\d+)', "react"),
    (r'react[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "react"),
    (r'Vue\.js\s+v(\d+\.\d+\.\d+)', "vue"),
    (r'vue@(\d+\.\d+\.\d+)', "vue"),
    (r'Lodash\s+v?(\d+\.\d+\.\d+)', "lodash"),
    (r'lodash[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "lodash"),
    (r'moment\.js\s+v?(\d+\.\d+\.\d+)', "moment"),
    (r'moment[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js', "moment"),
    (r'Bootstrap\s+v(\d+\.\d+\.\d+)', "bootstrap"),
    (r'bootstrap[.\-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)', "bootstrap"),
    (r'[Hh]andlebars\.js\s+v(\d+\.\d+\.\d+)', "handlebars"),
    (r'Underscore\.js\s+(\d+\.\d+\.\d+)', "underscore"),
    (r'Backbone\.js\s+(\d+\.\d+\.\d+)', "backbone"),
    (r'[Dd]3\.js\s+v?(\d+\.\d+\.\d+)', "d3"),
    (r'd3[.\-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js', "d3"),
    (r'axios\s+v(\d+\.\d+\.\d+)', "axios"),
    (r'[Ss]ocket\.IO\s+v?(\d+\.\d+\.\d+)', "socket.io"),
    (r'ag-[Gg]rid[^\d\n]{0,20}(\d+\.\d+\.\d+)', "ag-grid-community"),
    (r'ckeditor[.\-]?(\d+\.\d+\.\d+)', "ckeditor4"),
    (r'tinymce[.\-]?(\d+\.\d+\.\d+)', "tinymce"),
    (r'swagger-ui[.\-]?(\d+\.\d+\.\d+)', "swagger-ui"),
]

# A handful of the patterns above only ever appear in a filename
# (`jquery-3.5.1.min.js`), so they match the *URL* of a script, not its
# body. Those URLs aren't part of the beautified text, so scan them too.
_FILENAME_HINT = re.compile(r'\d+\.\d+\.\d+')


def detect_library_versions(all_js: str, urls: list[str] | None = None) -> list[dict]:
    """
    Scan combined JS text (and, optionally, the list of script URLs) for
    embedded library name/version banners and versioned filenames.

    Banner comments (common in unminified or lightly-minified bundles —
    beautify() run earlier makes these easy to spot) live in the body;
    versioned filenames (``jquery-3.5.1.min.js``) live in the URL, which is
    never part of the body — so both sources are scanned.

    Returns a deduplicated list of {"name": npm_package_name, "version": x.y.z}.
    Only as good as what's actually visible: minified bundles that strip
    comments and serve hashed filenames will yield fewer hits.
    """
    found: dict[tuple[str, str], dict] = {}

    def scan(text: str) -> None:
        for pattern, name in _LIB_VERSION_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                found.setdefault((name, m.group(1)), {"name": name, "version": m.group(1)})

    if all_js:
        scan(all_js)
    # Only bother scanning URLs that actually carry an x.y.z — keeps the
    # per-URL regex sweep off the (often thousands of) hash-named chunks.
    hinted = "\n".join(u for u in (urls or []) if _FILENAME_HINT.search(u))
    if hinted:
        scan(hinted)

    return sorted(found.values(), key=lambda l: (l["name"], l["version"]))


# ── CVSS v3.x base-score calculation ──────────────────────────────────────────
# OSV stores severity as a CVSS vector string, not a number. Turning it into a
# 0.0–10.0 base score (and a NONE/LOW/MEDIUM/HIGH/CRITICAL band) is what makes
# the output sortable and usable in a --fail-on gate. Formula: CVSS v3.1 spec,
# section 7.1. v3.0 uses the same base metrics, so one implementation covers both.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest 1-decimal number >= value (spec appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string, or None if it
    isn't a parseable v3 vector."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        c, i, a = _IMPACT[parts["C"]], _IMPACT[parts["I"]], _IMPACT[parts["A"]]
    except (KeyError, ValueError):
        return None

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_label(score: float | None) -> str:
    """CVSS v3.1 qualitative band for a numeric base score."""
    if score is None:
        return ""
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _best_cvss(vuln: dict) -> tuple[str, float | None]:
    """Pick the richest CVSS vector from an OSV record and score it.
    Returns (vector_string, numeric_score_or_None)."""
    fallback = ("", None)
    for sev in vuln.get("severity", []) or []:
        score_str = sev.get("score", "")
        if str(sev.get("type", "")).startswith("CVSS_V3") and score_str.startswith("CVSS:3"):
            return score_str, cvss3_base_score(score_str)
        if fallback == ("", None) and score_str:
            fallback = (score_str, None)   # keep a v4/unknown vector to at least display
    return fallback


def _label_for(vuln: dict, score: float | None) -> str:
    """Numeric band if we scored it, else OSV's own database_specific label."""
    if score is not None:
        return severity_label(score)
    db = (vuln.get("database_specific") or {}).get("severity", "")
    return str(db).upper() if db else ""


def _entry(lib: dict, vuln: dict) -> dict:
    """Shape one OSV vuln record into our CVE result dict."""
    vid = vuln.get("id", "")
    vector, score = _best_cvss(vuln)
    aliases = vuln.get("aliases") or []
    cve_id = next((a for a in aliases if a.startswith("CVE-")), "")
    summary = (vuln.get("summary") or vuln.get("details") or "").strip()
    return {
        "library": lib["name"],
        "version": lib["version"],
        "id": vid,
        "cve": cve_id,
        "summary": summary[:300],
        "severity": _label_for(vuln, score),
        "cvss_score": score,
        "cvss_vector": vector,
        "url": f"https://osv.dev/vulnerability/{vid}",
    }


_OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


def lookup_cves(libraries: list[dict], timeout: int = 10) -> list[dict]:
    """
    Match detected {name, version} libraries against OSV.dev — a free, public
    vulnerability database aggregating GitHub Security Advisories, npm
    advisories and NVD-derived records.

    One batched ``/querybatch`` request resolves every library to vuln IDs at
    once (instead of one request per library); full records are then fetched
    only for the IDs that actually matched, and shared across libraries so a
    vuln affecting several isn't fetched twice. Falls back to per-library
    ``/query`` if the batch endpoint is unreachable.

    Returns a list of:
      { library, version, id, cve, summary, severity, cvss_score, cvss_vector, url }
    """
    if not libraries:
        return []

    queries = [{"version": l["version"], "package": {"name": l["name"], "ecosystem": "npm"}}
               for l in libraries]
    try:
        resp = requests.post(_OSV_QUERYBATCH_URL, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        batch = resp.json().get("results", [])
    except requests.exceptions.RequestException as e:
        print(f"  {yellow('[WARN]')} OSV batch query failed ({e}); falling back to per-library lookups",
              file=sys.stderr)
        return _lookup_per_library(libraries, timeout)

    results: list[dict] = []
    detail_cache: dict[str, dict] = {}   # vuln id -> full record (shared across libs)
    for lib, res in zip(libraries, batch):
        for stub in (res or {}).get("vulns", []):
            vid = stub.get("id")
            if not vid:
                continue
            if vid not in detail_cache:
                detail_cache[vid] = _fetch_vuln(vid, timeout) or {"id": vid}
                time.sleep(0.1)          # polite pacing against the public API
            results.append(_entry(lib, detail_cache[vid]))
    return results


def _fetch_vuln(vuln_id: str, timeout: int) -> dict | None:
    """Fetch one full OSV record by ID (querybatch returns only id + modified)."""
    try:
        resp = requests.get(_OSV_VULN_URL + vuln_id, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f"  {yellow('[WARN]')} OSV detail fetch failed for {vuln_id}: {e}", file=sys.stderr)
        return None


def _lookup_per_library(libraries: list[dict], timeout: int) -> list[dict]:
    """Fallback path: one /query per library. /query returns full records, so
    no extra detail fetch is needed."""
    results: list[dict] = []
    for lib in libraries:
        payload = {"version": lib["version"], "package": {"name": lib["name"], "ecosystem": "npm"}}
        try:
            resp = requests.post(_OSV_QUERY_URL, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"  {yellow('[WARN]')} OSV lookup failed for {lib['name']}@{lib['version']}: {e}",
                  file=sys.stderr)
            continue
        for vuln in data.get("vulns", []):
            results.append(_entry(lib, vuln))
        time.sleep(0.2)
    return results
