"""
Dynamic extraction with headless Chromium (Playwright), honouring scope, scoped
auth, --proxy and --insecure.
"""


from ..net import Scope, ScopedAuth, build_auth_headers, build_cookies
from ..ui import cyan, red, yellow

# Optional — only needed for --dynamic
try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False


def extract_dynamic(url: str, args) -> tuple[list[str], list[str]]:
    """
    Launch a headless browser, wait for the page to fully load,
    and collect every script URL the browser actually requested.

    Returns (external_srcs, inline_blocks) same shape as extract_from_html.
    """
    if not PLAYWRIGHT_OK:
        print(red("[ERROR] Playwright not installed. Run: pip install playwright && playwright install chromium"))
        return [], []

    print(cyan("  [Browser] Launching headless Chromium..."))
    collected_urls = []
    inline_blocks = []

    proxy = getattr(args, "proxy", None)
    insecure = bool(getattr(args, "insecure", False))
    auth_mode = getattr(args, "auth_scope", "host") or "host"
    fetch_scope = Scope(url, getattr(args, "scope", "any") or "any",
                        getattr(args, "include_host", None), getattr(args, "exclude_host", None))

    # Auth headers are injected per-request (auth scope only) via a route
    # handler — NOT via extra_http_headers, which would send them everywhere.
    extra_headers = build_auth_headers(args)
    scope = ScopedAuth(url, extra_headers, {}, mode=auth_mode)

    # Cookies: host-only by default; with --auth-scope domain they're set on
    # the registrable domain so the browser sends them to its subdomains too.
    cookie_target = ({"domain": "." + scope.domain, "path": "/"} if auth_mode == "domain"
                     else {"url": url})
    pw_cookies = [
        {"name": k, "value": v, **cookie_target}
        for k, v in build_cookies(args).items()
    ]
    blocked = []

    # Any failure here (Chromium not installed, navigation error, page never
    # going network-idle, page crash) must not kill the whole run: whatever
    # was captured so far is returned and the static results still stand.
    try:
        with sync_playwright() as pw:
            launch_opts = {"headless": True}
            if proxy:
                launch_opts["proxy"] = {"server": proxy}
            browser = pw.chromium.launch(**launch_opts)
            try:
                # TLS errors are only ignored with --insecure (Chromium can't be
                # pointed at a CA file, so intercepting proxies need --insecure).
                context = browser.new_context(ignore_https_errors=insecure)
                if pw_cookies:
                    context.add_cookies(pw_cookies)
                if extra_headers or fetch_scope.restricted:
                    def route_handler(route, request):
                        # Out-of-scope requests never leave the browser
                        if not fetch_scope.allows(request.url) and request.url.startswith("http"):
                            blocked.append(request.url)
                            route.abort("blockedbyclient")
                        elif extra_headers and scope.in_scope(request.url):
                            route.continue_(headers={**request.headers, **extra_headers})
                        else:
                            route.continue_()
                    context.route("**/*", route_handler)

                page = context.new_page()

                # Intercept every network request ("request" also fires for
                # requests the route handler then aborts — skip those)
                def on_request(request):
                    if request.resource_type == "script" and fetch_scope.allows(request.url):
                        collected_urls.append(request.url)

                page.on("request", on_request)

                # SPAs with polling / websockets / analytics beacons often never
                # reach "networkidle". Wait for the load event first (hard
                # requirement), then give networkidle a bounded best-effort window.
                try:
                    page.goto(url, wait_until="load", timeout=30000)
                except PlaywrightTimeoutError:
                    print(f"  {yellow('[WARN]')} Page 'load' event not reached in 30s — using what loaded so far")
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except PlaywrightTimeoutError:
                    print(f"  {yellow('[WARN]')} Network never went idle (polling/websockets?) — continuing")

                # Extra time for late lazy-loaded chunks, while the request
                # listener is still active (the old sleep ran after collection).
                page.wait_for_timeout(2000)

                # Also grab inline scripts from the live DOM
                scripts = page.evaluate("""
                    () => Array.from(document.querySelectorAll('script:not([src])'))
                               .map(s => s.textContent)
                               .filter(t => t.trim().length > 0)
                """)
                inline_blocks.extend(s.strip() for s in scripts)
            finally:
                browser.close()
    except Exception as e:
        print(f"  {yellow('[WARN]')} Dynamic extraction failed ({type(e).__name__}: {str(e).splitlines()[0][:200] if str(e) else ''})"
              f" — continuing with {len(collected_urls)} script(s) captured so far")

    collected_urls = list(dict.fromkeys(collected_urls))
    if blocked:
        print(f"  {yellow('[Scope]')} Browser blocked {len(set(blocked))} out-of-scope request(s) "
              f"({fetch_scope.describe()})")
    print(cyan(f"  [Browser] Captured {len(collected_urls)} script request(s), {len(inline_blocks)} inline block(s)"))
    return collected_urls, inline_blocks

