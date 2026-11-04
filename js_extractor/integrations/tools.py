"""
External tools: katana, gau, httpx, wappalyzer, retire.js, semgrep, LinkFinder.
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..discovery.sourcemaps import SOURCE_EXTENSIONS, VENDOR_DIR_NAMES, is_vendor_path
from ..net import ScopedAuth
from ..ui import cyan, green, yellow


def run_line_tool(name: str, cmd: list[str], timeout: int, input_text: str = None):
    """
    Run a line-oriented CLI tool (katana, gau, httpx). On timeout the child is
    killed but everything it already printed is kept: subprocess attaches the
    partial output to TimeoutExpired (always as bytes), and an incomplete final
    line is dropped. Returns (lines, returncode, stderr) or None if the tool
    could not be started at all.
    """
    try:
        proc = subprocess.Popen(
            cmd, text=True, encoding="utf-8", errors="replace",
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except Exception as e:
        print(f"  {yellow('[WARN]')} {name} execution failed: {e}")
        return None

    try:
        out, err = proc.communicate(input_text, timeout=timeout)
        return [l.strip() for l in out.splitlines() if l.strip()], proc.returncode, err
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or b""
        try:
            # Documented pattern: kill, then communicate() again — it returns
            # everything the child wrote, including what was already buffered.
            proc.kill()
            out, _ = proc.communicate(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as kill_err:
            # Couldn't stop it (e.g. restricted sandbox): fall back to the
            # output captured up to the timeout and leave the child behind.
            print(f"  {yellow('[WARN]')} could not stop {name} (pid {proc.pid}): {kill_err}")
            out = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
    except Exception as e:
        print(f"  {yellow('[WARN]')} {name} execution failed: {e}")
        return None

    out = out or ""
    if out and not out.endswith("\n"):          # drop a half-written final line
        out = out.rsplit("\n", 1)[0] if "\n" in out else ""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    print(f"  {yellow('[WARN]')} {name} timed out after {timeout}s — keeping {len(lines)} "
          f"partial result line(s) (raise with --tool-timeout)")
    return lines, None, ""



def run_katana(url: str, depth: int = 2, headers: dict = None, cookies: dict = None,
                timeout: int = 180, scope_mode: str = "any", auth_mode: str = "host",
                proxy: str = None) -> list[str]:
    """
    Shell out to the katana crawler (ProjectDiscovery) to discover JS files
    across multiple pages of the site, beyond the single page fetched by
    requests/Playwright. Requires katana on PATH:
      go install github.com/projectdiscovery/katana/cmd/katana@latest

    Returns a deduplicated list of discovered .js URLs.
    """
    if shutil.which("katana") is None:
        print(f"  {yellow('[WARN]')} katana not found on PATH — skipping deep crawl.")
        print(f"  {yellow('[WARN]')} Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []

    cmd = ["katana", "-u", url, "-d", str(depth), "-silent", "-jc"]

    # katana's default field scope (rdn) covers the root domain and all its
    # subdomains, and it sends -H headers to every in-scope host. Narrow it
    # to the exact host for --scope host, and when credentials are supplied
    # with --auth-scope host (so they don't leak to sibling subdomains).
    if scope_mode == "host" or ((headers or cookies) and auth_mode == "host"):
        cmd += ["-fs", "fqdn"]
    if proxy:
        cmd += ["-proxy", proxy]

    # katana accepts repeated -H "Key: Value" for custom headers (auth, cookie, etc.)
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]

    print(f"  {cyan('[Katana]')} Crawling {url} (depth={depth})... this can take a while")
    res = run_line_tool("katana", cmd, timeout)
    if res is None:
        return []
    all_urls, rc, err = res
    if rc not in (0, None) and not all_urls:
        print(f"  {yellow('[WARN]')} katana exited with code {rc}: {err.strip()[:200]}")
        return []

    # katana's plain output mixes all discovered URLs, so filter to .js ourselves
    js_urls = sorted(set(u for u in all_urls if u.split("?")[0].endswith(".js")))
    print(f"  {green('[Katana]')} Discovered {len(js_urls)} additional JS file(s) via crawl")
    return js_urls



def _is_js_url(u: str) -> bool:
    return bool(re.search(r"\.m?js$", u.split("#")[0].split("?")[0]))



def run_gau(domain: str, providers: list[str] = None, timeout: int = 180,
            blacklist: str = "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,css",
            subs: bool = True) -> list[str]:
    """
    Shell out to gau (getallurls, lc/gau) to pull every URL ever seen for a
    domain across the Wayback Machine, AlienVault OTX, CommonCrawl and
    URLScan. This surfaces old/forgotten JS bundles, endpoints, and params
    that a live crawl (katana) would never find because the page no longer
    links to them. Requires gau on PATH:
      go install github.com/lc/gau/v2/cmd/gau@latest

    Returns a deduplicated list of URLs (all types — filter to .js yourself
    if you only want scripts).
    """
    if shutil.which("gau") is None:
        print(f"  {yellow('[WARN]')} gau not found on PATH — skipping historical URL collection.")
        print(f"  {yellow('[WARN]')} Install with: go install github.com/lc/gau/v2/cmd/gau@latest")
        return []

    # gau only queries public archives (not the target), so it is never sent
    # through --proxy. --subs is dropped for --scope host.
    cmd = ["gau"]
    if subs:
        cmd.append("--subs")
    if blacklist:
        cmd += ["--blacklist", blacklist]
    if providers:
        cmd += ["--providers", ",".join(providers)]
    cmd += [domain]

    print(f"  {cyan('[gau]')} Pulling historical URLs for {domain} (Wayback/OTX/CommonCrawl/URLScan)...")
    res = run_line_tool("gau", cmd, timeout)
    if res is None:
        return []
    lines, rc, err = res
    if rc not in (0, None) and not lines:
        print(f"  {yellow('[WARN]')} gau exited with code {rc}: {err.strip()[:200]}")
        return []

    urls = sorted(set(lines))
    print(f"  {green('[gau]')} Collected {len(urls)} historical URL(s)")
    return urls



def run_httpx_probe(urls: list[str], headers: dict = None, cookies: dict = None,
                     threads: int = 50, timeout: int = 300, target_url: str = "",
                     auth_mode: str = "host", proxy: str = None,
                     same_host_redirects: bool = False) -> list[dict]:
    """
    Probe URLs with httpx. Credentials (headers/cookies) are only used for
    URLs inside the auth scope; every other URL (other subdomains from
    gau --subs, third parties) is probed in a separate run without them.
    Callers filter `urls` by --scope beforehand; same_host_redirects stops
    httpx from following redirects off to other (possibly out-of-scope) hosts.
    """
    kw = {"threads": threads, "timeout": timeout, "proxy": proxy,
          "same_host_redirects": same_host_redirects}
    if not (headers or cookies) or not target_url:
        return _run_httpx(urls, headers, cookies, **kw)
    scope = ScopedAuth(target_url, {}, {}, mode=auth_mode)
    in_scope = [u for u in urls if scope.in_scope(u)]
    out_scope = [u for u in urls if not scope.in_scope(u)]
    return (_run_httpx(in_scope, headers, cookies, **kw)
            + _run_httpx(out_scope, None, None, **kw))



def _run_httpx(urls: list[str], headers: dict = None, cookies: dict = None,
               threads: int = 50, timeout: int = 300, proxy: str = None,
               same_host_redirects: bool = False) -> list[dict]:
    """
    Shell out to httpx (ProjectDiscovery's HTTP toolkit — NOT the Python
    `httpx` library) to probe a list of URLs and report which are alive,
    with status code, title, content-length and tech detection. Used to
    filter noisy gau output down to URLs that actually resolve today.
    Requires the httpx CLI on PATH:
      go install github.com/projectdiscovery/httpx/cmd/httpx@latest

    Returns a list of dicts (parsed from httpx's -json output), one per
    live URL.
    """
    if not urls:
        return []
    if shutil.which("httpx") is None:
        print(f"  {yellow('[WARN]')} httpx not found on PATH — skipping alive-check.")
        print(f"  {yellow('[WARN]')} Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return []

    cmd = ["httpx", "-silent", "-json",
           "-follow-host-redirects" if same_host_redirects else "-follow-redirects",
           "-status-code", "-title", "-content-length", "-tech-detect",
           "-threads", str(threads)]
    if proxy:
        cmd += ["-http-proxy", proxy]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]

    print(f"  {cyan('[httpx]')} Probing {len(urls)} URL(s) for liveness...")
    res = run_line_tool("httpx", cmd, timeout, input_text="\n".join(urls))
    if res is None:
        return []

    results = []
    for line in res[0]:
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    print(f"  {green('[httpx]')} {len(results)}/{len(urls)} URL(s) alive")
    return results



#
# These wrap the same command-line tools used in the manual workflow:
#   wappalyzer https://target.com
#   retire --path ./downloaded_js --outputformat json
#   semgrep --config "p/xss" ./downloaded_js
#   python3 linkfinder.py -i './downloaded_js/*.js' -o cli
#
# Each function checks the binary is on PATH first and degrades gracefully
# (prints a warning + install hint, returns an empty result) if it isn't —
# same pattern as run_katana() above.
def run_wappalyzer(url: str, timeout: int = 60) -> list[dict]:
    """
    Run the wappalyzer CLI (npm install -g wappalyzer) against the target
    URL for overall tech-stack fingerprinting (frameworks, servers, CMS,
    analytics, etc.) — broader than the in-JS signature matching we do
    ourselves in detect_frameworks()/detect_library_versions().

    Returns a list of {"name": str, "version": str, "categories": [str]}.
    """
    if shutil.which("wappalyzer") is None:
        print(f"  {yellow('[WARN]')} wappalyzer not found on PATH — skipping tech detection.")
        print(f"  {yellow('[WARN]')} Install: npm install -g wappalyzer")
        return []

    print(f"  {cyan('[Wappalyzer]')} Fingerprinting tech stack for {url}...")
    try:
        proc = subprocess.run(
            ["wappalyzer", url],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} wappalyzer timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} wappalyzer execution failed: {e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  {yellow('[WARN]')} Could not parse wappalyzer output as JSON")
        return []

    # Output shape varies across wappalyzer CLI versions/forks:
    #   {"urls": {...}, "technologies": [...]}  or a bare [...] list.
    # Categories may be dicts ({"name": ...}) or plain strings.
    if isinstance(data, dict):
        techs = data.get("technologies") or []
    elif isinstance(data, list):
        techs = data
    else:
        techs = []
    results = []
    for t in techs:
        if not isinstance(t, dict):
            continue
        cats = t.get("categories") or []
        results.append({
            "name": str(t.get("name") or "unknown"),
            "version": str(t.get("version") or ""),
            "categories": [
                str(c.get("name", "")) if isinstance(c, dict) else str(c)
                for c in (cats if isinstance(cats, list) else [])
            ],
        })

    print(f"  {green('[Wappalyzer]')} Identified {len(results)} technolog{'y' if len(results) == 1 else 'ies'}")
    return results



def run_retire(js_dirs: list[Path], timeout: int = 120) -> list[dict]:
    """
    Run retire.js (npm install -g retire) against every given directory —
    downloaded bundles, inline blocks AND source-map-recovered sources.
    Vendor code (node_modules/) is deliberately included here: recovered
    node_modules/<lib>/ files are exactly what retire.js fingerprints best.
    This is a local, signature-based CVE scanner — a useful complement to
    the live OSV.dev lookup in lookup_cves(), since it also catches
    hash-fingerprinted minified files that carry no version banner.

    Returns a list of {"file", "component", "version", "vulnerabilities": [...]}.
    """
    if shutil.which("retire") is None:
        print(f"  {yellow('[WARN]')} retire.js not found on PATH — skipping local CVE scan.")
        print(f"  {yellow('[WARN]')} Install: npm install -g retire")
        return []
    if not js_dirs:
        print(f"  {yellow('[WARN]')} No JS directory to scan with retire.js")
        return []

    results = []
    for d in js_dirs:
        results += _run_retire_dir(d, timeout)
    total_vulns = sum(len(r["vulnerabilities"]) for r in results)
    print(f"  {green('[retire.js]')} {len(results)} vulnerable component instance(s), "
          f"{total_vulns} finding(s) total")
    return results



def _run_retire_dir(js_dir: Path, timeout: int = 120) -> list[dict]:
    """retire.js against a single directory (it only accepts one --path)."""
    print(f"  {cyan('[retire.js]')} Scanning {js_dir} for known-vulnerable components...")
    try:
        proc = subprocess.run(
            ["retire", "--path", str(js_dir), "--outputformat", "json", "--severity", "low"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} retire.js timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} retire.js execution failed: {e}")
        return []

    # retire exits non-zero when it finds vulnerabilities — that's expected,
    # so don't treat returncode != 0 as failure; only missing JSON is fatal.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  {yellow('[WARN]')} Could not parse retire.js output as JSON")
        return []

    results = []
    for entry in data.get("data", []):
        fname = entry.get("file", "")
        for result in entry.get("results", []):
            component = result.get("component", "unknown")
            version = result.get("version", "")
            vulns = result.get("vulnerabilities", [])
            if vulns:
                results.append({
                    "file": fname,
                    "component": component,
                    "version": version,
                    "vulnerabilities": [
                        {
                            "info": v.get("info", []),
                            "identifiers": v.get("identifiers", {}),
                            "severity": v.get("severity", ""),
                        }
                        for v in vulns
                    ],
                })

    return results



def run_semgrep(target_dirs: list[Path], configs: list[str] = None, timeout: int = 300) -> list[dict]:
    """
    Run semgrep static analysis against downloaded bundles, inline blocks and
    source-map-recovered sources for dangerous client-side patterns (matches
    the manual step: `semgrep --config "p/xss" ./`). Recovered first-party
    sources are the most valuable target: readable, unminified code where
    source→sink flows are actually visible. Vendor code is excluded.

    Returns a list of {"rule_id", "file", "line", "message", "severity"}.
    """
    if shutil.which("semgrep") is None:
        print(f"  {yellow('[WARN]')} semgrep not found on PATH — skipping static analysis.")
        print(f"  {yellow('[WARN]')} Install: pip install semgrep  (or: pip install --break-system-packages semgrep)")
        return []
    if not target_dirs:
        print(f"  {yellow('[WARN]')} No JS directory to scan with semgrep")
        return []

    configs = configs or ["p/xss", "p/javascript"]
    cmd = ["semgrep", "--json", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    for d in VENDOR_DIR_NAMES:
        cmd += ["--exclude", d]
    cmd += [str(d) for d in target_dirs]

    where = ", ".join(str(d) for d in target_dirs)
    print(f"  {cyan('[semgrep]')} Running static analysis ({', '.join(configs)}) on {where}...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  {yellow('[WARN]')} semgrep timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"  {yellow('[WARN]')} semgrep execution failed: {e}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"  {yellow('[WARN]')} Could not parse semgrep output as JSON: {proc.stderr[:200]}")
        return []

    results = []
    for r in data.get("results", []):
        results.append({
            "rule_id": r.get("check_id", ""),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "message": (r.get("extra", {}).get("message", "") or "").strip()[:300],
            "severity": r.get("extra", {}).get("severity", ""),
        })

    print(f"  {green('[semgrep]')} {len(results)} finding(s)")
    return results



def run_linkfinder(target_dirs: list[Path], linkfinder_path: str = "", timeout: int = 120) -> list[str]:
    """
    Run LinkFinder (https://github.com/GerbenJavado/LinkFinder) against every
    script/source file in target_dirs (bundles, inline blocks, recovered
    .js/.ts/.vue/... sources; vendor code skipped) to extract endpoint-like
    strings — a complement to our own extract_endpoints() regex pass, using
    LinkFinder's own patterns.

    LinkFinder isn't a pip package with a stable console-script name, so this
    looks for (in order): an explicit --linkfinder-path, a `linkfinder`
    binary on PATH, or a `linkfinder.py` on PATH.

    Returns a deduplicated, sorted list of endpoint strings.
    """
    lf_cmd = None
    if linkfinder_path:
        lf_cmd = [sys.executable, linkfinder_path]
    elif shutil.which("linkfinder"):
        lf_cmd = ["linkfinder"]
    elif shutil.which("linkfinder.py"):
        lf_cmd = [sys.executable, shutil.which("linkfinder.py")]

    if lf_cmd is None:
        print(f"  {yellow('[WARN]')} LinkFinder not found — skipping.")
        print(f"  {yellow('[WARN]')} Install: git clone https://github.com/GerbenJavado/LinkFinder && "
              f"pip install -r LinkFinder/requirements.txt, then pass --linkfinder-path /path/to/linkfinder.py")
        return []
    js_files = [
        f for d in target_dirs for f in sorted(d.rglob("*"))
        if f.is_file() and f.suffix.lower() in SOURCE_EXTENSIONS and not is_vendor_path(f, d)
    ]
    if not js_files:
        print(f"  {yellow('[WARN]')} No script files under {', '.join(map(str, target_dirs))} for LinkFinder to scan")
        return []

    print(f"  {cyan('[LinkFinder]')} Scanning {len(js_files)} file(s)...")
    found = set()
    for jf in js_files:
        try:
            proc = subprocess.run(
                lf_cmd + ["-i", str(jf), "-o", "cli"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"  {yellow('[WARN]')} LinkFinder timed out on {jf.name}")
            continue
        except Exception as e:
            print(f"  {yellow('[WARN]')} LinkFinder failed on {jf.name}: {e}")
            continue
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                found.add(line)

    results = sorted(found)
    print(f"  {green('[LinkFinder]')} {len(results)} unique endpoint(s) found")
    return results

