"""
Library version fingerprinting and CVE lookup via OSV.dev.
"""
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



def detect_library_versions(all_js: str) -> list[dict]:
    """
    Scan combined JS text for embedded library name/version banners
    (common in unminified or lightly-minified bundles — beautify() run
    earlier in the pipeline makes these much easier to spot).

    Returns a deduplicated list of {"name": npm_package_name, "version": x.y.z}.
    Only as good as what's actually visible in the shipped JS: minified
    bundles that strip comments and rename everything will yield fewer hits.
    """
    found = {}
    for pattern, name in _LIB_VERSION_PATTERNS:
        for m in re.finditer(pattern, all_js, re.IGNORECASE):
            version = m.group(1)
            key = (name, version)
            if key not in found:
                found[key] = {"name": name, "version": version}
    return sorted(found.values(), key=lambda l: (l["name"], l["version"]))



_OSV_API_URL = "https://api.osv.dev/v1/query"



def lookup_cves(libraries: list[dict], timeout: int = 10) -> list[dict]:
    """
    For each detected {name, version}, query OSV.dev — a free, public
    vulnerability database that aggregates GitHub Security Advisories,
    npm advisories, and NVD-derived records. This mirrors what retire.js
    does locally, but stays current without needing a bundled/offline DB.

    Returns a list of:
      { library, version, id, cve, summary, severity, url }
    """
    results = []
    for lib in libraries:
        payload = {
            "version": lib["version"],
            "package": {"name": lib["name"], "ecosystem": "npm"},
        }
        try:
            resp = requests.post(_OSV_API_URL, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"  {yellow('[WARN]')} OSV lookup failed for {lib['name']}@{lib['version']}: {e}",
                  file=sys.stderr)
            continue

        for vuln in data.get("vulns", []):
            severity = ""
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    severity = sev.get("score", "")
                    break
            aliases = vuln.get("aliases", []) or []
            cve_id = next((a for a in aliases if a.startswith("CVE-")), "")
            summary = (vuln.get("summary") or vuln.get("details") or "").strip()
            results.append({
                "library": lib["name"],
                "version": lib["version"],
                "id": vuln.get("id", ""),
                "cve": cve_id,
                "summary": summary[:300],
                "severity": severity,
                "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
            })
        time.sleep(0.2)  # polite pacing against the public API

    return results

