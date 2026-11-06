"""
Wayback Machine: archived copies of scripts that are gone today.
"""
import json
import urllib.parse

import requests

from ..net import RateLimiter, fetch, looks_like_html


#
# Old bundles (found by gau, or referenced but 404 now) often still contain
# endpoints, params and keys that were removed from the current front end —
# while the backend routes frequently still exist. The CDX API finds the most
# recent 200 snapshot; /web/<ts>id_/<url> returns the original bytes without
# the Wayback toolbar.
WAYBACK_BASE = "https://web.archive.org"     # overridable (tests use a local stand-in)



WAYBACK_RATE = 1.0                           # req/s — archive.org is a shared public service



def make_wayback_session(max_bytes: int = 0) -> requests.Session:
    """Plain session for archive.org: no target credentials, no target scope, no --proxy."""
    s = requests.Session()
    s.headers.update({"User-Agent": "jxray (+https://github.com/sobishirvanloo/js-extractor-pro)"})
    s.limiter = RateLimiter(WAYBACK_RATE)
    s.max_bytes = max_bytes
    s.scope = None
    return s



def wayback_latest_snapshot(url: str, session: requests.Session):
    """(timestamp, original_url) of the newest 200 snapshot of `url`, or None."""
    candidates = [url]
    if "?" in url:                        # cache-busting query strings rarely match exactly
        candidates.append(url.split("?", 1)[0])
    for u in candidates:
        q = (f"{WAYBACK_BASE}/cdx/search/cdx?url={urllib.parse.quote(u, safe='')}"
             f"&output=json&fl=timestamp,original&filter=statuscode:200&limit=-1")
        resp = fetch(q, session, quiet=True)
        if resp is None:
            continue
        try:
            rows = json.loads(resp.text or "[]")
        except ValueError:
            continue
        # first row is the header ["timestamp", "original"]
        rows = [r for r in rows[1:] if isinstance(r, list) and len(r) >= 2]
        if rows:
            return rows[-1][0], rows[-1][1]
    return None



def fetch_from_wayback(url: str, session: requests.Session):
    """
    Archived copy of a dead script. Returns
    {url, snapshot, archive_url, text, headers} or None.
    """
    snap = wayback_latest_snapshot(url, session)
    if not snap:
        return None
    ts, original = snap
    archive_url = f"{WAYBACK_BASE}/web/{ts}id_/{original}"
    resp = fetch(archive_url, session, quiet=True)
    if resp is None or looks_like_html(resp.text):
        return None
    return {"url": url, "snapshot": ts, "archive_url": archive_url,
            "text": resp.text, "headers": resp.headers}



def wayback_url(timestamp: str, url: str) -> str:
    """Snapshot URL returning the original bytes (id_ = no Wayback toolbar)."""
    return f"{WAYBACK_BASE}/web/{timestamp}id_/{url}"
