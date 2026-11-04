#!/usr/bin/env python3
"""
JS Extractor & Beautifier  (v2)
================================
Extracts, beautifies, and analyzes all JavaScript from a web page.

Features:
  - Static extraction (requests + BeautifulSoup)
  - Dynamic extraction via headless Chromium (Playwright)  [--dynamic]
  - Follows JS imports/chunks referenced inside script files
  - Parses source maps (.js.map) to recover original pre-bundle code
  - Extracts JS from Web Workers and Service Workers
  - Framework detection (React, Vue, Angular, Next.js, Nuxt, Svelte ...)
  - Deep crawl via katana to discover additional JS across the site [--katana]
  - API endpoint discovery                                 [--endpoints]
  - Hidden/internal endpoint highlighting
  - Parameter extraction for fuzzing                       [--params]
  - Secret/token/key pattern detection
  - Library version fingerprinting + CVE lookup (OSV.dev)  [--cve]
  - HTML report generation

Usage:
  python3 js_extractor.py <url> [options]

Auth:
  --cookie "name=value; name2=value2"
  --jwt    "eyJ..."
  --header "Key: Value"            (repeatable)

Extraction:
  --dynamic                        Use headless browser (captures lazy-loaded JS)
  --katana                         Deep-crawl the site with katana to find more JS files
  --katana-depth N                 Crawl depth for katana (default: 2)
  --no-inline                      Skip inline <script> blocks
  --no-external                    Skip external .js files
  --no-workers                     Skip Web Workers / Service Workers
  --no-sourcemaps                  Skip source map recovery
  --no-imports                     Skip following import/require chains

Analysis:
  --endpoints                      Extract API endpoints from all JS
  --params                         Extract parameters for fuzzing
  --secrets                        Scan for leaked keys/tokens/passwords
  --cve                            Fingerprint library versions & check OSV.dev for known CVEs
  --wappalyzer                     Run wappalyzer CLI for overall tech-stack fingerprinting
  --retire                         Run retire.js against downloaded JS (local CVE signatures)
  --semgrep                        Run semgrep static analysis (default: p/xss, p/javascript)
  --semgrep-config RULESET         Add/override semgrep ruleset (repeatable)
  --linkfinder                     Run LinkFinder against downloaded JS for endpoint extraction
  --linkfinder-path PATH           Path to linkfinder.py if not on PATH
  --all-analysis                   Enable all analysis flags above

Note on DOM Invader: live source→sink tracing in the browser (Burp Suite's
DOM Invader) isn't automatable from the CLI — it needs a human driving the
browser. This tool prepares everything DOM Invader needs (beautified JS,
endpoints, params) but the live-tracing step itself stays manual.

Output:
  --output-dir  ./js_output        Output directory (default: ./js_output)
  --merge                          Combine all scripts into one file
  --report                         Generate HTML analysis report
"""

import argparse
import contextlib
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests  # noqa: F401  (re-exported: tests and library users use cli.requests)

# The package modules are imported absolutely so this file also works when run
# directly (`python js_extractor/cli.py`), where relative imports are unavailable.
# Names not used here are re-exported for library users and the test suites.
try:
    import js_extractor  # noqa: F401
except ImportError:                       # run directly as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_extractor.analyzers.dom import find_dom_issues, find_dom_issues_in_files, find_dom_sources
from js_extractor.analyzers.endpoints import (
    extract_endpoints,
    find_endpoints,
    find_endpoints_in_files,
    is_hidden_endpoint,
)
from js_extractor.analyzers.frameworks import detect_frameworks
from js_extractor.analyzers.params import extract_params
from js_extractor.analyzers.secrets import find_secrets, find_secrets_in_files, mask_secret
from js_extractor.analyzers.versions import detect_library_versions, lookup_cves
from js_extractor.discovery.chunks import (
    find_asset_paths,
    find_chunk_ids,
    find_chunk_templates,
    next_build_manifest_urls,
    parse_next_build_manifest,
    parse_vite_manifest,
)
from js_extractor.discovery.dynamic import extract_dynamic
from js_extractor.discovery.html import extract_from_html
from js_extractor.discovery.imports import find_js_imports, find_workers
from js_extractor.discovery.sourcemaps import (
    analysis_dirs,
    find_sourcemap_ref,
    is_vendor_path,
    parse_sourcemap,
    read_recovered_sources,
    safe_sourcemap_dest,
    try_recover_sourcemap,
)
from js_extractor.discovery.wayback import (
    fetch_from_wayback,
    make_wayback_session,
    wayback_latest_snapshot,
    wayback_url,
)
from js_extractor.integrations.tools import (
    _is_js_url,
    run_gau,
    run_httpx_probe,
    run_katana,
    run_line_tool,
    run_linkfinder,
    run_retire,
    run_semgrep,
    run_wappalyzer,
)
from js_extractor.net import (
    RateLimiter,
    Scope,
    ScopedAuth,
    base_domain,
    build_auth_headers,
    build_cookies,
    fetch,
    looks_like_html,
    make_session,
    safe_filename,
)
from js_extractor.output import beautify, save_js, write_results
from js_extractor.report import generate_report
from js_extractor.ui import bold, cyan, green, red, yellow

try:
    from js_extractor import __version__
except ImportError:                       # run directly as a script
    __version__ = "unknown"


FAIL_ON_CHOICES = ("secrets", "cves", "hidden-endpoints", "retire", "semgrep", "dom")



def main():
    parser = argparse.ArgumentParser(
        description="JS Extractor v2 — extract, beautify, and analyze all JS from a web page",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Target
    parser.add_argument("url", help="Target page URL")

    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--cookie", default="", metavar="STR",
        help='Cookie string, e.g. "session=abc; token=xyz"')
    auth.add_argument("--jwt", default="", metavar="TOKEN",
        help="JWT token (Bearer prefix optional)")
    auth.add_argument("--header", action="append", metavar="KEY:VAL",
        help="Custom header (repeatable)")
    auth.add_argument("--auth-scope", choices=("host", "domain"), default="host",
        help="Where --cookie/--jwt/--header are sent: 'host' = exact target host only (default); "
             "'domain' = target's registrable domain and all its subdomains")

    # Network
    net = parser.add_argument_group("Network")
    net.add_argument("--proxy", default=None, metavar="URL",
        help="Send all target traffic through this proxy, e.g. http://127.0.0.1:8080 (Burp) or "
             "socks5://127.0.0.1:9050. Applies to requests, --dynamic, katana and httpx; not to "
             "gau/OSV/semgrep, which only talk to public services")
    net.add_argument("--insecure", "-k", action="store_true",
        help="Skip TLS certificate verification (self-signed targets, intercepting proxies)")
    net.add_argument("--ca-cert", default=None, metavar="PATH",
        help="Verify TLS against this CA bundle (e.g. Burp's exported CA in PEM). "
             "Not usable by --dynamic: Chromium needs --insecure behind an intercepting proxy")

    # Performance
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--threads", "-t", type=int, default=5, metavar="N",
        help="Parallel script downloads (default: 5)")
    perf.add_argument("--rate-limit", type=float, default=10, metavar="RPS",
        help="Max requests per second across all threads, 0 = unlimited (default: 10)")
    perf.add_argument("--max-files", type=int, default=0, metavar="N",
        help="Download at most N external scripts, 0 = unlimited (default). Useful with --gau")
    perf.add_argument("--max-size", type=float, default=30, metavar="MB",
        help="Skip any response larger than this, 0 = unlimited (default: 30 MB)")

    # Scope
    scp = parser.add_argument_group("Scope")
    scp.add_argument("--scope", choices=Scope.MODES, default="any",
        help="Hosts the tool may send ANY request to: 'any' (default), 'domain' = target's "
             "registrable domain + subdomains, 'host' = exact target host only. Also narrows katana "
             "(-fs fqdn), gau (no --subs) and httpx (same-host redirects only), and makes --dynamic "
             "block out-of-scope browser requests")
    scp.add_argument("--include-host", action="append", metavar="PATTERN",
        help="Extra allowed host for --scope host/domain, glob allowed (e.g. 'cdn.example-static.com', "
             "'*.example.net'). Repeatable")
    scp.add_argument("--exclude-host", action="append", metavar="PATTERN",
        help="Never send requests to this host, glob allowed (e.g. '*.google-analytics.com'). "
             "Applies in every --scope mode and wins over --include-host. Repeatable")

    # Extraction
    ext = parser.add_argument_group("Extraction")
    ext.add_argument("--dynamic", action="store_true",
        help="Use headless Chromium to capture dynamically loaded scripts")
    ext.add_argument("--katana", action="store_true",
        help="Deep-crawl the site with katana (must be installed) to discover JS files beyond the single page")
    ext.add_argument("--katana-depth", type=int, default=2, metavar="N",
        help="Crawl depth for --katana (default: 2)")
    ext.add_argument("--gau", action="store_true",
        help="Pull historical URLs for the target domain via gau (Wayback/OTX/CommonCrawl/URLScan), "
             "then feed discovered .js URLs into extraction (must be installed)")
    ext.add_argument("--gau-providers", default="", metavar="LIST",
        help="Comma-separated gau providers, e.g. 'wayback,otx' (default: all)")
    ext.add_argument("--httpx-probe", action="store_true",
        help="Probe --gau results with httpx to keep only URLs that are alive today "
             "(must be installed; without this flag, gau results are used unfiltered)")
    ext.add_argument("--no-inline", action="store_true",
        help="Skip inline <script> blocks")
    ext.add_argument("--no-external", action="store_true",
        help="Skip external .js files")
    ext.add_argument("--no-workers", action="store_true",
        help="Skip Web Worker and Service Worker scripts")
    ext.add_argument("--no-sourcemaps", action="store_true",
        help="Skip source map recovery")
    ext.add_argument("--wayback", action="store_true",
        help="Fetch Wayback Machine copies of scripts that are gone today (404/410, or an HTML page "
             "instead of JS) — mostly old bundles found by --gau — and analyse them with the rest. "
             "Talks to web.archive.org directly (not via --proxy), ~1 request/second")
    ext.add_argument("--wayback-max", type=int, default=50, metavar="N",
        help="Look up at most N dead scripts in the Wayback Machine (default: 50)")
    ext.add_argument("--no-chunks", action="store_true",
        help="Skip lazy-chunk discovery (webpack runtime chunk maps, Next.js _buildManifest, "
             "Vite manifest / preload lists)")
    ext.add_argument("--no-imports", action="store_true",
        help="Skip following import/require chains")

    # Analysis
    ana = parser.add_argument_group("Analysis")
    ana.add_argument("--endpoints", action="store_true",
        help="Extract API endpoints (includes hidden/internal detection)")
    ana.add_argument("--params", action="store_true",
        help="Extract parameters for fuzzing; saves params.txt wordlist")
    ana.add_argument("--dom", action="store_true",
        help="Map DOM XSS sinks (innerHTML, eval, location, ...), sources (location.hash, ...) and "
             "postMessage handlers without origin checks, ranked by source→sink flow; saves dom_sinks.json")
    ana.add_argument("--secrets", action="store_true",
        help="Scan for leaked keys, tokens, passwords")
    ana.add_argument("--cve", action="store_true",
        help="Fingerprint library versions in the JS and check OSV.dev for known CVEs")
    ana.add_argument("--wappalyzer", action="store_true",
        help="Run wappalyzer CLI for overall tech-stack fingerprinting (requires: npm install -g wappalyzer)")
    ana.add_argument("--retire", action="store_true",
        help="Run retire.js against downloaded JS for local signature-based CVE scanning (requires: npm install -g retire)")
    ana.add_argument("--semgrep", action="store_true",
        help="Run semgrep static analysis on downloaded JS (requires: pip install semgrep)")
    ana.add_argument("--semgrep-config", action="append", metavar="RULESET",
        help="Semgrep config/ruleset, repeatable (default: p/xss and p/javascript)")
    ana.add_argument("--linkfinder", action="store_true",
        help="Run LinkFinder against downloaded JS for endpoint extraction (needs LinkFinder installed separately)")
    ana.add_argument("--linkfinder-path", default="", metavar="PATH",
        help="Path to linkfinder.py if it's not on PATH as 'linkfinder'")
    ana.add_argument("--tool-timeout", type=int, default=None, metavar="SECONDS",
        help="Timeout for each external tool run (katana, gau, httpx, wappalyzer, retire, semgrep, "
             "LinkFinder per file). Default: per-tool (60-300s). On timeout, partial katana/gau/httpx "
             "output is kept.")
    ana.add_argument("--all-analysis", action="store_true",
        help="Enable --endpoints, --params, --secrets, --cve, --wappalyzer, --retire, --semgrep, and --linkfinder together")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--output-dir", default="./js_output", metavar="DIR",
        help="Output directory (default: ./js_output)")
    out.add_argument("--merge", action="store_true",
        help="Combine all scripts into ALL_SCRIPTS_MERGED.js")
    out.add_argument("--report", action="store_true",
        help="Generate an HTML analysis report")
    out.add_argument("--json", action="store_true",
        help="Print machine-readable results (same as results.json, which is always written) to "
             "stdout; all progress output goes to stderr")
    out.add_argument("--fail-on", default="", metavar="LIST",
        help="Exit with code 3 if any of these were found (comma-separated): "
             f"{', '.join(FAIL_ON_CHOICES)}. For CI / scripting")

    args = parser.parse_args()

    fail_on = [f.strip() for f in args.fail_on.split(",") if f.strip()]
    bad = [f for f in fail_on if f not in FAIL_ON_CHOICES]
    if bad:
        parser.error(f"--fail-on: unknown value(s) {', '.join(bad)}; choose from {', '.join(FAIL_ON_CHOICES)}")
    if not 1 <= args.threads <= 64:
        parser.error("--threads must be between 1 and 64")
    if args.rate_limit < 0 or args.max_files < 0 or args.max_size < 0:
        parser.error("--rate-limit, --max-files and --max-size must not be negative")
    if args.wayback_max < 1:
        parser.error("--wayback-max must be at least 1")

    # --json: stdout carries only the JSON document; all progress → stderr
    if args.json:
        json_stream = sys.stdout
        with contextlib.redirect_stdout(sys.stderr):
            code = _run(args, parser, fail_on, json_stream)
    else:
        code = _run(args, parser, fail_on, None)
    if code:
        sys.exit(code)



def _run(args, parser, fail_on: list, json_stream) -> int:
    """Everything after argument parsing. Returns the process exit code."""
    started = time.monotonic()

    # --all-analysis shortcut
    if args.all_analysis:
        args.endpoints = args.params = args.secrets = args.cve = args.dom = True
        args.wappalyzer = args.retire = args.semgrep = args.linkfinder = True

    # --fail-on X implies the analysis that produces X (otherwise it could
    # never trigger and a CI gate would silently always pass)
    for f, flag in (("secrets", "secrets"), ("cves", "cve"), ("hidden-endpoints", "endpoints"), ("dom", "dom"),
                    ("retire", "retire"), ("semgrep", "semgrep")):
        if f in fail_on:
            setattr(args, flag, True)

    if args.tool_timeout is not None and args.tool_timeout <= 0:
        parser.error("--tool-timeout must be a positive number of seconds")
    # Passed as **kwargs so each tool keeps its own default unless overridden
    tool_timeout = {"timeout": args.tool_timeout} if args.tool_timeout else {}

    # ── Network / scope validation ───────────────────────────────────────────
    if not urlparse(args.url).scheme in ("http", "https") or not urlparse(args.url).hostname:
        parser.error(f"target must be an absolute http(s) URL, got: {args.url!r}")
    if args.proxy:
        p = urlparse(args.proxy)
        if p.scheme not in ("http", "https", "socks5", "socks5h", "socks4") or not p.hostname or not p.port:
            parser.error("--proxy must look like http://HOST:PORT or socks5://HOST:PORT")
        if p.scheme.startswith("socks"):
            try:
                import socks  # noqa: F401  (PySocks, needed by requests for SOCKS)
            except ImportError:
                parser.error('SOCKS proxies need PySocks: pip install "requests[socks]"')
    if args.insecure and args.ca_cert:
        parser.error("use either --insecure or --ca-cert, not both")
    if args.ca_cert and not Path(args.ca_cert).is_file():
        parser.error(f"--ca-cert file not found: {args.ca_cert}")
    if args.include_host and args.scope == "any":
        print(f"{yellow('[WARN]')} --include-host has no effect with --scope any")

    scope = Scope(args.url, args.scope, args.include_host, args.exclude_host)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    limiter = RateLimiter(args.rate_limit)
    max_bytes = int(args.max_size * 1048576) if args.max_size else 0
    session = make_session(args, scope, limiter, max_bytes)
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Step 1: Fetch the page ────────────────────────────────────────────────
    print(f"\n{bold('[*]')} Target: {cyan(args.url)}")
    print(f"    Scope: {scope.describe()}   Auth scope: "
          f"{'*.' + base_domain(urlparse(args.url).hostname) if args.auth_scope == 'domain' else urlparse(args.url).hostname}")
    if args.proxy:
        tls = "insecure" if args.insecure else (f"CA {args.ca_cert}" if args.ca_cert else "verified")
        print(f"    Proxy: {args.proxy}   TLS: {tls}")
        if not (args.insecure or args.ca_cert):
            print(f"    {yellow('[WARN]')} Intercepting proxies (Burp/ZAP) re-sign TLS: add --ca-cert "
                  f"<proxy CA .pem> or --insecure, else HTTPS fetches will fail")
        if args.dynamic and not args.insecure:
            print(f"    {yellow('[WARN]')} --dynamic behind an intercepting proxy needs --insecure "
                  f"(Chromium can't load a CA file)")
        if args.wappalyzer:
            print(f"    {yellow('[WARN]')} wappalyzer runs its own browser and does NOT use --proxy")
    if args.wappalyzer and scope.restricted:
        print(f"    {yellow('[WARN]')} wappalyzer loads the page in its own browser and does NOT honour --scope")
    print()
    resp = fetch(args.url, session)
    if not resp:
        write_results(output_dir / "results.json", {
            "tool": "js-extractor", "version": __version__, "target": args.url,
            "error": f"could not fetch target ({session.fetch_error or 'error'})",
        }, json_stream)
        return 1
    base_html = resp.text

    # Tech-stack fingerprinting (independent of JS extraction, so run it first)
    wappalyzer_techs = []
    if args.wappalyzer:
        print(f"{bold('[*]')} Tech-stack fingerprinting...")
        wappalyzer_techs = run_wappalyzer(args.url, **tool_timeout)
        if wappalyzer_techs:
            for t in wappalyzer_techs:
                cats = f" [{', '.join(t['categories'])}]" if t["categories"] else ""
                ver = f" v{t['version']}" if t["version"] else ""
                print(f"    - {t['name']}{ver}{cats}")
        print()

    # ── Step 2: Collect script URLs ───────────────────────────────────────────
    static_ext, static_inline = extract_from_html(base_html, args.url)

    if args.dynamic:
        dynamic_ext, dynamic_inline = extract_dynamic(args.url, args)
        # Merge: static first, then any new URLs/blocks from dynamic pass
        all_ext_urls = list(dict.fromkeys(static_ext + dynamic_ext))
        all_inline   = static_inline + [b for b in dynamic_inline if b not in static_inline]
    else:
        all_ext_urls = static_ext
        all_inline   = static_inline

    if args.katana:
        katana_js = run_katana(
            args.url,
            depth=args.katana_depth,
            headers=build_auth_headers(args),
            cookies=build_cookies(args),
            scope_mode=args.scope,
            auth_mode=args.auth_scope,
            proxy=args.proxy,
            **tool_timeout,
        )
        all_ext_urls = list(dict.fromkeys(all_ext_urls + katana_js))

    # JS URLs known to be gone today (httpx said 404/410 or nothing) — seeds
    # for --wayback, alongside the 404s found while downloading
    wayback_seed = []

    # ── gau: historical URL collection, optionally filtered through httpx ─────
    if args.gau:
        domain = urlparse(args.url).hostname
        providers = [p.strip() for p in args.gau_providers.split(",") if p.strip()] or None
        gau_urls = run_gau(domain, providers=providers, subs=(args.scope != "host"), **tool_timeout)
        if scope.restricted and gau_urls:
            kept = [u for u in gau_urls if scope.allows(u)]
            if len(kept) != len(gau_urls):
                print(f"  {yellow('[Scope]')} Dropped {len(gau_urls) - len(kept)} out-of-scope gau URL(s)")
            gau_urls = kept

        if gau_urls:
            if args.httpx_probe:
                alive = run_httpx_probe(
                    gau_urls,
                    headers=build_auth_headers(args),
                    cookies=build_cookies(args),
                    target_url=args.url,
                    auth_mode=args.auth_scope,
                    proxy=args.proxy,
                    same_host_redirects=scope.restricted,
                    **tool_timeout,
                )
                alive_path = output_dir / "gau_alive.txt"
                with alive_path.open("w", encoding="utf-8") as f:
                    for r in alive:
                        f.write(f"{r.get('status_code', '?')}  {r.get('url', '')}\n")
                print(f"  Saved -> {alive_path}")
                usable_urls = [r["url"] for r in alive if r.get("url")]
                status = {r.get("url"): r.get("status_code") for r in alive}
                wayback_seed += [u for u in gau_urls if _is_js_url(u)
                                 and (u not in status or status[u] in (404, 410))]
            else:
                gau_all_path = output_dir / "gau_all.txt"
                gau_all_path.write_text("\n".join(gau_urls), encoding="utf-8")
                print(f"  Saved -> {gau_all_path}")
                usable_urls = gau_urls

            gau_js = sorted(set(u for u in usable_urls if _is_js_url(u)))
            print(f"  {green('[gau]')} {len(gau_js)} JS file(s) from gau results queued for extraction")
            all_ext_urls = list(dict.fromkeys(all_ext_urls + gau_js))

    # Inline blocks can reference scripts too — service worker registration
    # and inline <script type="module"> imports usually live there. Resolve
    # against the final page URL (after redirects).
    if not args.no_inline and all_inline:
        page_url = resp.url or args.url
        from_inline = []
        for code in all_inline:
            if not args.no_workers:
                from_inline += find_workers(code, page_url)
            if not args.no_imports:
                from_inline += find_js_imports(code, page_url)
        new = [u for u in dict.fromkeys(from_inline) if u not in all_ext_urls]
        if new:
            print(f"  {green('[Inline]')} {len(new)} worker/import script(s) referenced from inline blocks")
            all_ext_urls = all_ext_urls + new

    # Out-of-scope scripts are listed (not fetched) so the tester can decide
    # whether to widen the scope with --include-host.
    out_of_scope = [u for u in all_ext_urls if not scope.allows(u)]
    all_ext_urls = [u for u in all_ext_urls if scope.allows(u)]

    print(f"{bold('[*]')} Discovered: {len(all_ext_urls)} external script(s), {len(all_inline)} inline block(s)"
          + (f", {len(out_of_scope)} out of scope (not fetched)" if out_of_scope else "") + "\n")

    # Accumulate all JS text for analysis and optional merge
    all_js_text = ""
    all_contents_merge = []
    file_records = []         # for report
    workers_to_fetch = set()
    imports_to_fetch = set()
    recovered_paths = []      # source-map-recovered files written this run
    # (path shown to the user, text, lines prepended on disk) — lets secret
    # findings point at the real file and line instead of a concatenated blob
    analysis_files = []

    # ── Step 3: Download & beautify external scripts ──────────────────────────
    skipped = {"failed": [], "too_large": [], "not_javascript": [], "max_files": [], "guess_missed": []}
    page_url = resp.url or args.url
    archived, wayback_stats = [], {"candidates": 0, "found": 0}

    # Lazy-chunk discovery state. Chunk URLs built from bundler metadata are
    # "guesses": fetched quietly, and a miss (404, or the index.html an SPA
    # server returns for any path) is recorded as guess_missed, not an error.
    chunk_templates, chunk_ids, routes, vite_sources = [], set(), set(), []
    guessed = set()
    chunk_stats = {"webpack_runtimes": 0, "candidates": 0, "found": 0}

    def add_guesses(urls):
        new = [u for u in urls if u and u not in guessed and u not in all_ext_urls]
        guessed.update(new)
        return new

    if not args.no_chunks and not args.no_external:
        # CRA inlines the webpack runtime into index.html by default
        if not args.no_inline:
            for code in all_inline:
                chunk_templates += find_chunk_templates(code, page_url)
                chunk_ids |= find_chunk_ids(code)
        # Next.js: _buildManifest.js from the buildId, even if not referenced
        all_ext_urls += add_guesses(next_build_manifest_urls(base_html, all_ext_urls, page_url))
        # Vite: build manifest, if it was deployed publicly
        for mpath in ("/.vite/manifest.json", "/manifest.json"):
            mresp = fetch(urljoin(page_url, mpath), session, quiet=True)
            if mresp is not None and not looks_like_html(mresp.text):
                files, sources = parse_vite_manifest(mresp.text, urljoin(page_url, "/"))
                if files:
                    print(f"  {green('[Chunks]')} Vite manifest {mpath}: {len(files)} chunk(s), "
                          f"{len(sources)} source path(s)")
                    vite_sources += sources
                    all_ext_urls += [u for u in files if u not in all_ext_urls]

    if not args.no_external:
        ext_dir = output_dir / "external"
        local = threading.local()
        target_cookies = session.cookies.copy()      # cookies the target set on page load

        def thread_session():
            if not hasattr(local, "session"):
                local.session = make_session(args, scope, limiter, max_bytes, target_cookies)
            return local.session

        def download(idx: int, src_url: str, is_guess: bool) -> dict:
            """Network + CPU part, run in worker threads. No shared state touched."""
            s = thread_session()
            if not is_guess:
                print(f"  {cyan('[DL]')} {src_url}")
            js_resp = fetch(src_url, s, quiet=is_guess)
            if not js_resp:
                return {"idx": idx, "url": src_url, "guess": is_guess, "error": s.fetch_error or "error"}
            raw = js_resp.text
            if looks_like_html(raw):
                if not is_guess:
                    print(f"  {yellow('[SKIP]')} {src_url} returned an HTML page, not JS (soft 404 / login / WAF?)")
                return {"idx": idx, "url": src_url, "guess": is_guess, "error": "not_javascript"}
            if is_guess:
                print(f"  {green('[Chunk]')} {src_url}")
            recovered = []
            if not args.no_sourcemaps:
                try_recover_sourcemap(raw, src_url, s, output_dir,
                                      headers=js_resp.headers, written=recovered)
            chunks = {}
            if not args.no_chunks:
                next_chunks, next_routes = parse_next_build_manifest(raw, src_url)
                chunks = {
                    "templates": find_chunk_templates(raw, src_url),
                    "ids": find_chunk_ids(raw),
                    "urls": find_asset_paths(raw, src_url, page_url) + next_chunks,
                    "routes": next_routes,
                }
            return {
                "idx": idx, "url": src_url, "guess": is_guess, "error": None,
                "beautified": beautify(raw),
                "recovered": recovered,
                "imports": [] if args.no_imports else find_js_imports(raw, src_url),
                "workers": [] if args.no_workers else find_workers(raw, src_url),
                "chunks": chunks,
            }

        def chunk_candidates() -> list:
            """Every chunk URL the known runtimes can build from all ids seen so far."""
            urls = []
            for t in chunk_templates:
                for cid in sorted(t.known_ids | chunk_ids):
                    urls.append(t.url_for(cid, page_url))
            return add_guesses(u for u in urls if u not in seen)

        # Breadth-first in waves: each wave downloads in parallel, then results
        # are handled in submission order, so file numbering and analysis
        # output are identical from run to run regardless of thread timing.
        seen, pending, n_queued = set(), list(all_ext_urls), 0
        pending += chunk_candidates()                  # from an inline runtime
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            while pending:
                wave = []
                for u in pending:
                    if u in seen:
                        continue
                    seen.add(u)
                    if not scope.allows(u):            # imports/workers found along the way
                        out_of_scope.append(u)
                    elif args.max_files and n_queued >= args.max_files:
                        skipped["max_files"].append(u)
                    else:
                        n_queued += 1
                        wave.append((n_queued, u, u in guessed))
                pending = []

                for res in pool.map(lambda w: download(*w), wave):
                    if res["error"] == "out_of_scope":   # redirected out of scope
                        out_of_scope.append(res["url"])
                        continue
                    if res["error"]:
                        if res["guess"] and res["error"] != "too_large":
                            key = "guess_missed"
                        else:
                            key = res["error"] if res["error"] in skipped else "failed"
                            # gone today (404/410, or the SPA's index.html) → try the archive
                            if res["error"] in ("http_404", "http_410", "not_javascript"):
                                wayback_seed.append(res["url"])
                        skipped[key].append(res["url"])
                        continue
                    if res["guess"]:
                        chunk_stats["found"] += 1
                    ch = res["chunks"]
                    if ch:
                        chunk_templates.extend(ch["templates"])
                        chunk_ids.update(ch["ids"])
                        routes.update(ch["routes"])
                        pending += add_guesses(u for u in ch["urls"] if u not in seen)
                    src_url, beautified = res["url"], res["beautified"]
                    all_js_text += beautified + "\n"
                    fname = safe_filename(src_url, prefix=f"ext_{res['idx']:03d}")
                    fpath = ext_dir / fname
                    header_lines = save_js(beautified, fpath, url=src_url)
                    analysis_files.append((str(fpath.relative_to(output_dir)), beautified, header_lines))
                    file_records.append({"kind": "external", "filename": fname,
                                         "url": src_url, "saved_path": str(fpath.relative_to(output_dir)),
                                         "size_kb": fpath.stat().st_size / 1024})
                    recovered_paths.extend(res["recovered"])
                    imports_to_fetch.update(res["imports"])
                    workers_to_fetch.update(res["workers"])
                    pending += [u for u in res["imports"] + res["workers"] if u not in seen]
                    all_contents_merge.append(
                        f"\n\n{'='*70}\n// FILE: {fname}\n// SOURCE: {src_url}\n{'='*70}\n\n"
                        + beautified
                    )

                # New runtimes/ids from this wave → more chunk URLs for the next
                if not args.no_chunks:
                    pending += chunk_candidates()

        chunk_stats["webpack_runtimes"] = len(chunk_templates)
        chunk_stats["candidates"] = len(guessed)
        if guessed:
            print(f"\n  {green('[Chunks]')} {chunk_stats['found']} lazy chunk(s) found from "
                  f"{len(guessed)} candidate URL(s) ({len(chunk_templates)} webpack runtime(s), "
                  f"{len(routes)} route(s))")
        if routes:
            routes_path = output_dir / "routes.txt"
            routes_path.write_text("\n".join(sorted(routes)) + "\n", encoding="utf-8")
            print(f"  Routes -> {routes_path}")

        if skipped["max_files"]:
            print(f"\n  {yellow('[Limit]')} --max-files {args.max_files} reached: "
                  f"{len(skipped['max_files'])} script(s) not downloaded")

        # ── Wayback: archived copies of scripts that are gone today ───────────
        dead = [u for u in dict.fromkeys(wayback_seed) if scope.allows(u)]
        wayback_stats["candidates"] = len(dead)
        if args.wayback and dead:
            todo = dead[: args.wayback_max]
            print(f"\n{bold('[Wayback]')} Looking up {len(todo)} dead script(s) in the Wayback Machine"
                  + (f" (capped by --wayback-max {args.wayback_max}; {len(dead) - len(todo)} more)"
                     if len(dead) > len(todo) else "") + "...")
            wb = make_wayback_session(max_bytes)
            arch_dir = output_dir / "archived"
            for i, url in enumerate(todo, 1):
                got = fetch_from_wayback(url, wb)
                if not got:
                    continue
                print(f"  {green('[Archived]')} {url}  (snapshot {got['snapshot']})")
                beautified = beautify(got["text"])
                all_js_text += beautified + "\n"
                fname = safe_filename(url, prefix=f"wb_{i:03d}")
                fpath = arch_dir / fname
                header_lines = save_js(beautified, fpath, url=got["archive_url"])
                analysis_files.append((str(fpath.relative_to(output_dir)), beautified, header_lines))
                file_records.append({"kind": "archived", "filename": fname, "url": url,
                                     "archive_url": got["archive_url"], "snapshot": got["snapshot"],
                                     "saved_path": str(fpath.relative_to(output_dir)),
                                     "size_kb": fpath.stat().st_size / 1024})
                archived.append({"url": url, "snapshot": got["snapshot"],
                                 "archive_url": got["archive_url"],
                                 "saved_path": str(fpath.relative_to(output_dir))})
                # Old source maps are often archived too: resolve the map URL
                # against the ORIGINAL script URL (urljoin on the archive URL
                # would mangle the embedded "http://"), then fetch its snapshot.
                if not args.no_sourcemaps:
                    ts = got["snapshot"]
                    try_recover_sourcemap(got["text"], url, wb, output_dir,
                                          headers=got["headers"], written=recovered_paths,
                                          rewrite_url=lambda u, ts=ts: wayback_url(ts, u))
            wayback_stats["found"] = len(archived)
            print(f"  {green('[Wayback]')} {len(archived)}/{len(todo)} recovered from the archive -> {arch_dir}")
        elif dead and not args.wayback:
            print(f"\n  {cyan('[Hint]')} {len(dead)} script(s) are gone today (404 / HTML instead of JS) — "
                  f"add --wayback to fetch archived copies")

    if out_of_scope:
        oos_path = output_dir / "out_of_scope.txt"
        oos_path.write_text("\n".join(dict.fromkeys(out_of_scope)) + "\n", encoding="utf-8")
        print(f"\n  {yellow('[Scope]')} {len(set(out_of_scope))} out-of-scope script URL(s) not fetched "
              f"({scope.describe()}) -> {oos_path}")

    # ── Step 4: Inline script blocks ──────────────────────────────────────────
    if not args.no_inline and all_inline:
        inline_dir = output_dir / "inline"
        print(f"\n{bold('[*]')} Saving {len(all_inline)} inline block(s)...")
        for i, code in enumerate(all_inline, 1):
            beautified = beautify(code)
            all_js_text += beautified + "\n"
            fname = f"inline_{i:03d}.js"
            fpath = inline_dir / fname
            header_lines = save_js(beautified, fpath)
            analysis_files.append((str(fpath.relative_to(output_dir)), beautified, header_lines))
            size_kb = fpath.stat().st_size / 1024
            file_records.append({"kind": "inline", "filename": fname,
                                  "url": f"{args.url}#inline-{i}", "saved_path": str(fpath.relative_to(output_dir)),
                                  "size_kb": size_kb})
            all_contents_merge.append(
                f"\n\n{'='*70}\n// INLINE BLOCK {i}\n{'='*70}\n\n" + beautified
            )

    # ── Step 5: Merge ─────────────────────────────────────────────────────────
    if args.merge and all_contents_merge:
        merged_path = output_dir / "ALL_SCRIPTS_MERGED.js"
        banner = (
            f"/* {'='*66}\n"
            f"   Merged JS dump\n"
            f"   Source: {args.url}\n"
            f"   Sections: {len(all_contents_merge)}\n"
            f"   {'='*66} */\n"
        )
        merged_path.write_text(banner + "".join(all_contents_merge), encoding="utf-8")
        print(f"\n{green('[*]')} Merged -> {merged_path}")

    # ══════════════════════════════════════════════════════════════════════════
    # Analysis phase
    # ══════════════════════════════════════════════════════════════════════════

    report_data = {
        "target_url": args.url,
        "total_files": len(file_records),
        "total_size_kb": sum(f["size_kb"] for f in file_records),
        "files": file_records,
        "technologies": wappalyzer_techs,
    }

    # Fold source-map-recovered originals into the analysis. First-party code
    # feeds every regex pass; vendor (node_modules) code only feeds framework
    # and library-version detection, where it helps instead of adding noise.
    sm_root = (output_dir / "sourcemap_recovered").resolve()
    sm_app_files, sm_vendor_text, n_sm_vendor = read_recovered_sources(recovered_paths, sm_root)
    n_sm_app = len(sm_app_files)
    if n_sm_app or n_sm_vendor:
        print(f"\n{bold('[SourceMap]')} Including {n_sm_app} first-party + {n_sm_vendor} vendor "
              f"recovered source file(s) in analysis")
    out_root = output_dir.resolve()
    for p, text in sm_app_files:
        all_js_text += text + "\n"
        analysis_files.append((str(p.relative_to(out_root)), text, 0))
    fingerprint_text = all_js_text + sm_vendor_text
    report_data["sourcemap_files"] = {"first_party": n_sm_app, "vendor": n_sm_vendor}
    report_data["routes"] = sorted(routes)
    report_data["chunks"] = chunk_stats

    # Framework detection (always runs if we have JS)
    frameworks = detect_frameworks(fingerprint_text) if fingerprint_text else []
    report_data["frameworks"] = frameworks
    if frameworks:
        print(f"\n{bold('[Framework]')} Detected: {', '.join(yellow(f) for f in frameworks)}")

    # Endpoints
    report_data["endpoints"] = []
    report_data["hidden_endpoints"] = []
    report_data["endpoint_details"] = []
    if args.endpoints and analysis_files:
        print(f"\n{bold('[Endpoints]')} Scanning...")
        details = find_endpoints_in_files(analysis_files)
        endpoints = [d["path"] for d in details]
        hidden = [d["path"] for d in details if d["hidden"]]
        report_data["endpoints"] = endpoints
        report_data["hidden_endpoints"] = hidden
        report_data["endpoint_details"] = details

        ep_path = output_dir / "endpoints.txt"
        ep_path.write_text("\n".join(endpoints), encoding="utf-8")
        hidden_path = output_dir / "endpoints_hidden.txt"
        hidden_path.write_text("\n".join(hidden), encoding="utf-8")

        with_method = sum(1 for d in details if d["methods"])
        print(f"  Found {green(str(len(endpoints)))} endpoint(s), {with_method} with a known HTTP method  "
              f"({red(str(len(hidden)))} flagged as hidden/internal)")
        if hidden:
            print(f"  {red('[!] Hidden/Internal endpoints:')}")
            for d in (d for d in details if d["hidden"]):
                methods = ",".join(d["methods"]) or "?"
                print(f"      {red(d['path'])}  [{methods}]  {d['file']}:{d['line']}")
        print(f"  Saved -> {ep_path}")
        print(f"  Saved -> {hidden_path}")

    # Parameters
    report_data["params"] = []
    report_data["wordlist_path"] = ""
    if args.params and analysis_files:
        print(f"\n{bold('[Params]')} Extracting for fuzzing...")
        params = extract_params("\n".join(t for _, t, _ in analysis_files), base_html)
        report_data["params"] = params

        wordlist_path = output_dir / "params_wordlist.txt"
        wordlist_path.write_text("\n".join(params), encoding="utf-8")
        report_data["wordlist_path"] = str(wordlist_path)

        print(f"  Found {green(str(len(params)))} unique parameter(s)")
        print(f"  Wordlist -> {wordlist_path}")

    # Secrets
    report_data["secrets"] = []
    if args.secrets and analysis_files:
        print(f"\n{bold('[Secrets]')} Scanning for leaked credentials...")
        secrets = find_secrets_in_files(analysis_files)
        report_data["secrets"] = secrets

        # Full, unmasked values + every location: needed to validate findings.
        # Terminal and HTML report only ever show masked values.
        secrets_path = output_dir / "secrets.json"
        secrets_path.write_text(json.dumps(secrets, indent=2, ensure_ascii=False), encoding="utf-8")

        if secrets:
            counts = {k: sum(1 for s in secrets if s["severity"] == k) for k in ("high", "medium", "low")}
            print(f"  {red(f'[!] {len(secrets)} potential secret(s):')} {counts['high']} high, "
                  f"{counts['medium']} medium, {counts['low']} low (public-by-design keys)")
            for s in secrets:
                more = f" (+{len(s['locations']) - 1} more)" if len(s["locations"]) > 1 else ""
                colour = red if s["severity"] == "high" else (yellow if s["severity"] == "medium" else (lambda t: t))
                note = f"  — {s['note']}" if s.get("note") else ""
                print(f"      {colour('[' + s['severity'] + '] ' + s['type'])} {mask_secret(s['value'])}  "
                      f"{s['file']}:{s['line']}{more}{note}")
        else:
            print(f"  {green('No secrets detected.')}")
        print(f"  Saved -> {secrets_path}  (unmasked — handle with care)")

    # DOM XSS sinks / sources / postMessage
    report_data["dom_findings"] = []
    report_data["dom_sources"] = []
    if args.dom and analysis_files:
        print(f"\n{bold('[DOM]')} Taint analysis: sources → sinks, postMessage handlers...")
        dom, dom_sources = find_dom_issues_in_files(analysis_files)
        report_data["dom_findings"] = dom
        report_data["dom_sources"] = dom_sources
        dom_path = output_dir / "dom_sinks.json"
        dom_path.write_text(json.dumps(dom, indent=2, ensure_ascii=False), encoding="utf-8")
        src_path = output_dir / "dom_sources.json"
        src_path.write_text(json.dumps(dom_sources, indent=2, ensure_ascii=False), encoding="utf-8")
        counts = {s: sum(1 for d in dom if d["severity"] == s) for s in ("high", "medium", "low")}
        flows = sum(1 for d in dom if d.get("trace"))
        print(f"  {red(str(counts['high']) + ' high')}, {yellow(str(counts['medium']) + ' medium')}, "
              f"{counts['low']} low  —  {flows} with a traced source→sink flow, "
              f"{len(dom_sources)} source read(s) inventoried")
        for d in [d for d in dom if d["severity"] != "low"][:15]:
            colour = red if d["severity"] == "high" else yellow
            print(f"    {colour('[' + d['severity'] + ']')} {d['sink']}  ({d['kind']}, confidence {d['confidence']})"
                  f"  {d['file']}:{d['line']}")
            if d.get("trace_text"):
                print(f"        {d['trace_text'][:160]}")
            else:
                print(f"        {d['snippet'][:140]}")
            if d.get("note"):
                print(f"        note: {d['note']}")
        print(f"  Saved -> {dom_path}")
        print(f"  Saved -> {src_path}")

    # Library versions + CVE matching
    report_data["libraries"] = []
    report_data["cves"] = []
    if args.cve and fingerprint_text:
        print(f"\n{bold('[CVE]')} Fingerprinting library versions...")
        libs = detect_library_versions(fingerprint_text)
        report_data["libraries"] = libs

        if not libs:
            print("  No version-fingerprinted libraries detected "
                  "(minified bundles often strip the banner comments this relies on).")
        else:
            print(f"  Detected {green(str(len(libs)))} version-fingerprinted librar{'y' if len(libs) == 1 else 'ies'}:")
            for l in libs:
                print(f"    - {l['name']} v{l['version']}")

            print(f"  {bold('[CVE]')} Querying OSV.dev for known vulnerabilities...")
            cves = lookup_cves(libs)
            report_data["cves"] = cves

            cve_path = output_dir / "cve_report.txt"
            with cve_path.open("w", encoding="utf-8") as f:
                for c in cves:
                    label = c["cve"] or c["id"]
                    f.write(f"{c['library']}@{c['version']}  {label}  "
                            f"(severity: {c['severity'] or 'n/a'})\n"
                            f"  {c['summary']}\n  {c['url']}\n\n")

            if cves:
                plural = "y" if len(cves) == 1 else "ies"
                print(f"  {red(f'[!] {len(cves)} known vulnerabilit{plural} found:')}")
                for c in cves:
                    label = c["cve"] or c["id"]
                    print(f"      {red(label)} - {c['library']}@{c['version']} - {c['summary'][:80]}")
            else:
                print(f"  {green('No known CVEs found for the detected versions.')}")
            print(f"  Saved -> {cve_path}")

    # retire.js — local signature-based CVE scan of the downloaded external JS
    report_data["retire_findings"] = []
    if args.retire:
        print(f"\n{bold('[retire.js]')} Scanning downloaded JS for known-vulnerable components...")
        retire_findings = run_retire(analysis_dirs(output_dir), **tool_timeout)
        report_data["retire_findings"] = retire_findings
        if retire_findings:
            retire_path = output_dir / "retire_report.txt"
            with retire_path.open("w", encoding="utf-8") as f:
                for r in retire_findings:
                    f.write(f"{r['file']}  ->  {r['component']}@{r['version']}\n")
                    for v in r["vulnerabilities"]:
                        ids = v.get("identifiers", {})
                        cve = ids.get("CVE", [ids.get("summary", "")])
                        f.write(f"    [{v.get('severity', 'n/a')}] {', '.join(cve) if isinstance(cve, list) else cve}\n")
                    f.write("\n")
            print(f"  Saved -> {retire_path}")

    # semgrep — static analysis for dangerous client-side patterns
    report_data["semgrep_findings"] = []
    if args.semgrep:
        print(f"\n{bold('[semgrep]')} Running static analysis...")
        semgrep_findings = run_semgrep(analysis_dirs(output_dir), configs=args.semgrep_config, **tool_timeout)
        report_data["semgrep_findings"] = semgrep_findings
        if semgrep_findings:
            semgrep_path = output_dir / "semgrep_report.txt"
            with semgrep_path.open("w", encoding="utf-8") as f:
                for s in semgrep_findings:
                    f.write(f"[{s['severity']}] {s['rule_id']}\n  {s['file']}:{s['line']}\n  {s['message']}\n\n")
            for s in semgrep_findings[:10]:
                print(f"    {red('[' + s['severity'] + ']')} {s['rule_id']} — {s['file']}:{s['line']}")
            print(f"  Saved -> {semgrep_path}")

    # LinkFinder — supplemental endpoint extraction
    report_data["linkfinder_endpoints"] = []
    if args.linkfinder:
        print(f"\n{bold('[LinkFinder]')} Extracting endpoints from downloaded JS...")
        lf_endpoints = run_linkfinder(analysis_dirs(output_dir), linkfinder_path=args.linkfinder_path,
                                      **tool_timeout)
        report_data["linkfinder_endpoints"] = lf_endpoints
        if lf_endpoints:
            lf_path = output_dir / "linkfinder_endpoints.txt"
            lf_path.write_text("\n".join(lf_endpoints), encoding="utf-8")
            print(f"  Saved -> {lf_path}")

    # HTML report
    if args.report:
        rpath = generate_report(report_data, output_dir)
        print(f"\n{green('[Report]')} HTML report -> {rpath}")

    # ── Machine-readable results ──────────────────────────────────────────────
    hits = {
        # low = public-by-design keys: listed, but never fail a --fail-on secrets gate
        "secrets": sum(1 for s in report_data.get("secrets", []) if s["severity"] != "low"),
        "cves": len(report_data.get("cves", [])),
        "hidden-endpoints": len(report_data.get("hidden_endpoints", [])),
        "dom": sum(1 for d in report_data.get("dom_findings", []) if d["severity"] == "high"),
        "retire": sum(len(r["vulnerabilities"]) for r in report_data.get("retire_findings", [])),
        "semgrep": len(report_data.get("semgrep_findings", [])),
    }
    results = {
        "tool": "js-extractor",
        "version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "target": args.url,
        "final_url": resp.url,
        "scope": {"mode": args.scope, "allowed": scope.describe(), "auth_scope": args.auth_scope},
        "stats": {
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "external_downloaded": sum(1 for f in file_records if f["kind"] == "external"),
            "inline_blocks": sum(1 for f in file_records if f["kind"] == "inline"),
            "sourcemap_files": report_data.get("sourcemap_files", {}),
            "chunks": chunk_stats,
            "wayback": wayback_stats,
            "out_of_scope": len(set(out_of_scope)),
            **{f"skipped_{k}": len(v) for k, v in skipped.items()},
            "findings": hits,
        },
        "files": [{k: f[k] for k in ("kind", "url", "saved_path")} | {"size_kb": round(f["size_kb"], 1)}
                  for f in file_records],
        "frameworks": report_data.get("frameworks", []),
        "technologies": report_data.get("technologies", []),
        "endpoints": report_data.get("endpoints", []),
        "endpoint_details": report_data.get("endpoint_details", []),
        "hidden_endpoints": report_data.get("hidden_endpoints", []),
        "params": report_data.get("params", []),
        "secrets": report_data.get("secrets", []),          # unmasked, like secrets.json
        "dom_findings": report_data.get("dom_findings", []),
        "dom_sources": report_data.get("dom_sources", []),
        "libraries": report_data.get("libraries", []),
        "cves": report_data.get("cves", []),
        "retire_findings": report_data.get("retire_findings", []),
        "semgrep_findings": report_data.get("semgrep_findings", []),
        "linkfinder_endpoints": report_data.get("linkfinder_endpoints", []),
        "routes": sorted(routes),
        "archived": archived,
        "vite_manifest_sources": vite_sources,
        "out_of_scope": list(dict.fromkeys(out_of_scope)),
        "skipped": skipped,
    }
    results_path = output_dir / "results.json"
    write_results(results_path, results, json_stream)

    # ── Summary ───────────────────────────────────────────────────────────────
    js_files = list(output_dir.rglob("*.js"))
    total_kb = sum(f.stat().st_size for f in js_files) / 1024
    print(f"\n{'─'*55}")
    print(f"{green('[+]')} Done in {results['stats']['elapsed_seconds']:.1f}s — "
          f"{len(js_files)} JS file(s), {total_kb:.1f} KB total")
    # guess_missed is expected (most guessed chunk URLs are probes), not a problem
    real_skips = {k: v for k, v in skipped.items() if v and k != "guess_missed"}
    if real_skips:
        print("    Skipped: " + ", ".join(f"{len(v)} {k.replace('_', ' ')}" for k, v in real_skips.items())
              + "  (see results.json)")
    print(f"    Output dir: {output_dir.resolve()}")
    print(f"    Results:    {results_path}")
    print(f"{'─'*55}")
    print(f"{cyan('[Manual step]')} Live source→sink tracing (DOM Invader in Burp Suite) "
          f"isn't automatable — load {args.url} in a Burp-proxied browser with DOM Invader "
          f"enabled and use the beautified JS + endpoints/params above as your map.\n")

    triggered = [f for f in fail_on if hits.get(f)]
    if triggered:
        print(f"{red('[FAIL]')} --fail-on matched: " + ", ".join(f"{f} ({hits[f]})" for f in triggered))
        return 3
    return 0



if __name__ == "__main__":
    main()

