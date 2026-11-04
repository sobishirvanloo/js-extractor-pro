"""
Static HTML extraction: <script> tags, <base href>, preload/modulepreload links.
"""


from bs4 import BeautifulSoup

from ..net import resolve


def extract_from_html(html: str, base_url: str):
    """
    Parse HTML for <script> tags.

    Returns:
      external_srcs : list[str]  -- absolute URLs from <script src="...">
      inline_blocks : list[str]  -- raw JS text from inline <script> tags
    """
    soup = BeautifulSoup(html, "html.parser")
    external_srcs, inline_blocks = [], []

    # <base href> changes how every relative URL on the page resolves
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_url = resolve(base_tag["href"], base_url) or base_url

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            url = resolve(src, base_url)
            if url:
                external_srcs.append(url)
        else:
            code = tag.string or tag.get_text()
            if code and code.strip():
                inline_blocks.append(code.strip())

    # Scripts the page only preloads (Vite emits modulepreload for every
    # chunk of the entry; Next/webpack use preload/prefetch as=script).
    for tag in soup.find_all("link", href=True):
        rel = {r.lower() for r in (tag.get("rel") or [])}
        is_script = (tag.get("as") or "").lower() == "script"
        if "modulepreload" in rel or (is_script and rel & {"preload", "prefetch"}):
            url = resolve(tag["href"], base_url)
            if url:
                external_srcs.append(url)

    return list(dict.fromkeys(external_srcs)), inline_blocks

