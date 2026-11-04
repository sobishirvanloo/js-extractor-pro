"""
Self-contained HTML report (every target-derived value is escaped).
"""
from collections import defaultdict
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlparse

from .analyzers.secrets import mask_secret


def generate_report(data: dict, out_dir: Path) -> Path:
    """Build a self-contained HTML analysis report."""
    # Everything in `data` comes from the target (JS contents, URLs, tool
    # output) and must be treated as hostile: escape every interpolated value
    # and only allow http(s) links. The CSP below is defence in depth.
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def e(value) -> str:
        return html_escape(str(value), quote=True)

    def safe_href(url) -> str:
        url = str(url).strip()
        return e(url) if urlparse(url).scheme.lower() in ("http", "https") else "#"

    def badge(text, color):
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{e(text)}</span>'

    def section(title, content_html, color="#2563eb"):
        return f"""
        <details open>
          <summary style="cursor:pointer;padding:10px;background:{color}15;border-left:4px solid {color};
                          font-weight:bold;font-size:15px;list-style:none">{title}</summary>
          <div style="padding:12px 16px">{content_html}</div>
        </details>"""

    # ── Files table ──────────────────────────────────────────────────────────
    file_rows = ""
    for f in data.get("files", []):
        kind_badge = badge(f["kind"], {"external": "#6366f1", "archived": "#a16207"}.get(f["kind"], "#0891b2"))
        if f.get("snapshot"):
            kind_badge += f'<br><a href="{safe_href(f.get("archive_url", ""))}" target="_blank" rel="noopener noreferrer" style="font-size:11px">snapshot {e(f["snapshot"])}</a>'
        file_rows += f"""<tr>
          <td>{kind_badge}</td>
          <td style="word-break:break-all"><a href="{e(f['saved_path'])}" target="_blank" rel="noopener noreferrer">{e(f['filename'])}</a></td>
          <td><a href="{safe_href(f['url'])}" target="_blank" rel="noopener noreferrer" style="font-size:11px">{e(f['url'][:80])}{'...' if len(f['url'])>80 else ''}</a></td>
          <td>{f['size_kb']:.1f} KB</td>
        </tr>"""
    files_html = f"""
    <table style="width:100%;border-collapse:collapse">
      <tr style="background:#f1f5f9;font-weight:bold">
        <th style="padding:8px;text-align:left">Type</th>
        <th style="padding:8px;text-align:left">File</th>
        <th style="padding:8px;text-align:left">Source URL</th>
        <th style="padding:8px;text-align:left">Size</th>
      </tr>
      {file_rows}
    </table>"""

    # ── Frameworks ───────────────────────────────────────────────────────────
    fw_html = " ".join(badge(f, "#7c3aed") for f in data.get("frameworks", [])) or "<i>None detected</i>"

    # ── Endpoints ────────────────────────────────────────────────────────────
    ep_rows = ""
    details = data.get("endpoint_details") or [
        {"path": p, "methods": [], "hidden": p in data.get("hidden_endpoints", []), "file": "", "line": ""}
        for p in data.get("endpoints", [])]
    for d in details:
        flag = f' {badge("HIDDEN", "#dc2626")}' if d["hidden"] else ""
        methods = " ".join(badge(m, "#0f766e") for m in d["methods"])
        where = f"{e(d['file'])}:{e(d['line'])}" if d.get("file") else ""
        ep_rows += (f"<tr><td style='padding:5px;white-space:nowrap'>{methods}</td>"
                    f"<td style='padding:5px;font-family:monospace;word-break:break-all'>{e(d['path'])}{flag}</td>"
                    f"<td style='padding:5px;font-family:monospace;font-size:11px;color:#64748b;word-break:break-all'>{where}</td></tr>\n")
    ep_html = f"<table style='width:100%;border-collapse:collapse'>{ep_rows}</table>" if ep_rows else "<i>No endpoints extracted (use --endpoints)</i>"

    # ── Params ───────────────────────────────────────────────────────────────
    param_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;display:inline-block">{e(p)}</code>'
        for p in data.get("params", [])
    ) or "<i>No params extracted (use --params)</i>"

    # Wordlist file path
    wordlist_note = ""
    if data.get("params"):
        wordlist_note = f'<p style="margin-top:8px">📄 Wordlist saved to: <code>{e(data.get("wordlist_path",""))}</code></p>'

    # ── Secrets ──────────────────────────────────────────────────────────────
    sec_rows = ""
    for s in data.get("secrets", []):
        locs = s.get("locations") or [{"file": s.get("file", ""), "line": s["line"]}]
        loc_html = "<br>".join(f"{e(l['file'])}:{e(l['line'])}" for l in locs[:5])
        if len(locs) > 5:
            loc_html += f"<br><i>+{len(locs) - 5} more (see secrets.json)</i>"
        sec_rows += (
            f"<tr>"
            f"<td style='padding:5px'>{badge(s.get('severity', 'medium'), {'high': '#dc2626', 'medium': '#d97706', 'low': '#64748b'}.get(s.get('severity'), '#d97706'))} "
            f"{badge(s['type'], '#475569')}"
            + (f"<br><small>{e(s['note'])}</small>" if s.get("note") else "") +
            f"</td>"
            f"<td style='padding:5px;font-family:monospace'>{e(mask_secret(s['value']))}</td>"
            f"<td style='padding:5px;font-family:monospace;font-size:12px;word-break:break-all'>{loc_html}</td>"
            f"</tr>\n"
        )
    sec_html = (
        f"<table style='width:100%;border-collapse:collapse'>{sec_rows}</table>"
        if sec_rows else "<i>No secrets found (use --secrets)</i>"
    )

    # ── DOM sinks ────────────────────────────────────────────────────────────
    dom_all = data.get("dom_findings", [])
    dom_shown = [d for d in dom_all if d["severity"] != "low"][:300]
    sev_colour = {"high": "#dc2626", "medium": "#d97706", "low": "#64748b"}
    dom_rows = ""
    for d in dom_shown:
        more = f" <i>(+{len(d['locations']) - 1} more)</i>" if len(d.get("locations", [])) > 1 else ""
        meta = f"<br><small>{e(d.get('kind', ''))} · confidence {e(d.get('confidence', '?'))}</small>"
        trace = (f"<div style='margin-top:4px;color:#0f766e'>{e(d['trace_text'])}</div>"
                 if d.get("trace_text") else "")
        note = f"<div style='margin-top:4px;color:#64748b'><i>{e(d['note'])}</i></div>" if d.get("note") else ""
        dom_rows += (
            f"<tr><td style='padding:5px'>{badge(d['severity'], sev_colour[d['severity']])}</td>"
            f"<td style='padding:5px;font-size:12px'>{e(d['sink'])}{meta}</td>"
            f"<td style='padding:5px;font-family:monospace;font-size:12px;word-break:break-all'>"
            f"{e(d['file'])}:{e(d['line'])}{more}</td>"
            f"<td style='padding:5px;font-family:monospace;font-size:12px;word-break:break-all'>{e(d['snippet'])}"
            f"{trace}{note}</td></tr>\n"
        )
    n_low = sum(1 for d in dom_all if d["severity"] == "low")
    if dom_rows:
        dom_html = (f"<table style='width:100%;border-collapse:collapse'>"
                    f"<tr style='background:#f1f5f9;font-weight:bold'><th style='padding:8px;text-align:left'>Severity</th>"
                    f"<th style='padding:8px;text-align:left'>Sink</th><th style='padding:8px;text-align:left'>Location</th>"
                    f"<th style='padding:8px;text-align:left'>Code</th></tr>{dom_rows}</table>")
    else:
        dom_html = "<i>No high/medium DOM findings (or --dom was not used)</i>"
    if n_low:
        dom_html += f"<p><i>+ {n_low} low-severity sink(s) with no known source nearby — see dom_sinks.json</i></p>"

    # ── Libraries & CVEs ─────────────────────────────────────────────────────
    cves_by_lib = defaultdict(list)
    for c in data.get("cves", []):
        cves_by_lib[(c["library"], c["version"])].append(c)

    lib_rows = ""
    for l in data.get("libraries", []):
        key = (l["name"], l["version"])
        hits = cves_by_lib.get(key, [])
        if hits:
            cve_badges = " ".join(
                f'<a href="{safe_href(c["url"])}" target="_blank" rel="noopener noreferrer">{badge(c["cve"] or c["id"], "#dc2626")}</a>'
                for c in hits
            )
            status = cve_badges
        else:
            status = badge("no known CVEs", "#16a34a")
        lib_rows += f"""<tr>
          <td style="padding:5px;font-family:monospace">{e(l['name'])}</td>
          <td style="padding:5px;font-family:monospace">{e(l['version'])}</td>
          <td style="padding:5px">{status}</td>
        </tr>"""
    lib_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">Library</th>
                <th style="padding:8px;text-align:left">Version</th>
                <th style="padding:8px;text-align:left">Known CVEs (via OSV.dev)</th>
              </tr>{lib_rows}
            </table>"""
        if lib_rows else "<i>No version-fingerprinted libraries detected (use --cve)</i>"
    )

    cve_detail_rows = ""
    for c in data.get("cves", []):
        cve_detail_rows += f"""<tr>
          <td style="padding:5px">{badge(c['cve'] or c['id'], '#dc2626')}</td>
          <td style="padding:5px;font-family:monospace">{e(c['library'])}@{e(c['version'])}</td>
          <td style="padding:5px">{e(c['severity']) if c['severity'] else '<i>n/a</i>'}</td>
          <td style="padding:5px;font-size:12px">{e(c['summary'])}</td>
          <td style="padding:5px"><a href="{safe_href(c['url'])}" target="_blank" rel="noopener noreferrer">osv.dev</a></td>
        </tr>"""
    cve_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">ID</th>
                <th style="padding:8px;text-align:left">Library</th>
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">Summary</th>
                <th style="padding:8px;text-align:left">Link</th>
              </tr>{cve_detail_rows}
            </table>"""
        if cve_detail_rows else "<i>No known CVEs matched (or --cve was not used)</i>"
    )

    # ── Technologies (wappalyzer) ────────────────────────────────────────────
    tech_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;display:inline-block">'
        f'{e(t["name"])}{" v" + e(t["version"]) if t["version"] else ""}</code>'
        for t in data.get("technologies", [])
    ) or "<i>No tech-stack data (use --wappalyzer)</i>"

    # ── retire.js findings ───────────────────────────────────────────────────
    retire_rows = ""
    for r in data.get("retire_findings", []):
        for v in r["vulnerabilities"]:
            ids = v.get("identifiers", {})
            cve_list = ids.get("CVE", [])
            label = ", ".join(cve_list) if cve_list else (ids.get("summary", "") or "unlabeled")
            retire_rows += f"""<tr>
              <td style="padding:5px">{badge(label, '#dc2626')}</td>
              <td style="padding:5px;font-family:monospace">{e(r['component'])}@{e(r['version'])}</td>
              <td style="padding:5px">{e(v.get('severity', '')) if v.get('severity') else '<i>n/a</i>'}</td>
              <td style="padding:5px;font-size:12px;word-break:break-all">{e(r['file'])}</td>
            </tr>"""
    retire_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">ID</th>
                <th style="padding:8px;text-align:left">Component</th>
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">File</th>
              </tr>{retire_rows}
            </table>"""
        if retire_rows else "<i>No retire.js findings (or --retire was not used)</i>"
    )

    # ── semgrep findings ──────────────────────────────────────────────────────
    semgrep_rows = ""
    for s in data.get("semgrep_findings", []):
        semgrep_rows += f"""<tr>
          <td style="padding:5px">{badge(s['severity'] or 'INFO', '#b45309')}</td>
          <td style="padding:5px;font-family:monospace;font-size:12px">{e(s['rule_id'])}</td>
          <td style="padding:5px;font-size:12px">{e(s['file'])}:{e(s['line'])}</td>
          <td style="padding:5px;font-size:12px">{e(s['message'])}</td>
        </tr>"""
    semgrep_html = (
        f"""<table style='width:100%;border-collapse:collapse'>
              <tr style="background:#f1f5f9;font-weight:bold">
                <th style="padding:8px;text-align:left">Severity</th>
                <th style="padding:8px;text-align:left">Rule</th>
                <th style="padding:8px;text-align:left">Location</th>
                <th style="padding:8px;text-align:left">Message</th>
              </tr>{semgrep_rows}
            </table>"""
        if semgrep_rows else "<i>No semgrep findings (or --semgrep was not used)</i>"
    )

    # ── LinkFinder endpoints ──────────────────────────────────────────────────
    lf_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;'
        f'display:inline-block;word-break:break-all">{e(lf)}</code>'
        for lf in data.get("linkfinder_endpoints", [])
    ) or "<i>No LinkFinder results (or --linkfinder was not used)</i>"

    # ── Routes (Next.js build manifest) ───────────────────────────────────────
    route_chips = "".join(
        f'<code style="margin:2px;padding:3px 7px;background:#f1f5f9;border-radius:4px;'
        f'display:inline-block;word-break:break-all">{e(r)}</code>'
        for r in data.get("routes", [])
    ) or "<i>No client-side routes recovered</i>"
    ch = data.get("chunks") or {}
    if ch.get("candidates"):
        route_chips = (f"<p>Lazy chunks: <b>{e(ch.get('found', 0))}</b> found from {e(ch['candidates'])} "
                       f"candidate URLs ({e(ch.get('webpack_runtimes', 0))} webpack runtime(s))</p>"
                       + route_chips)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>JS Extractor Report — {e(data['target_url'])}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 0; background: #f8fafc; color: #1e293b; }}
  .wrap {{ max-width: 1100px; margin: auto; padding: 24px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 20px; min-width: 120px; }}
  .stat-num {{ font-size: 28px; font-weight: bold; color: #2563eb; }}
  .stat-lbl {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
  details {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  table tr:nth-child(even) {{ background: #f8fafc; }}
  a {{ color: #2563eb; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔍 JS Extractor Report</h1>
  <div class="meta">
    Target: <a href="{safe_href(data['target_url'])}" target="_blank" rel="noopener noreferrer">{e(data['target_url'])}</a>
    &nbsp;|&nbsp; Generated: {ts}
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-num">{data['total_files']}</div><div class="stat-lbl">JS Files</div></div>
    <div class="stat"><div class="stat-num">{data['total_size_kb']:.0f} KB</div><div class="stat-lbl">Total Size</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('endpoints', []))}</div><div class="stat-lbl">Endpoints</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('hidden_endpoints', []))}</div><div class="stat-lbl">Hidden Endpoints</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('params', []))}</div><div class="stat-lbl">Parameters</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('secrets', []))}</div><div class="stat-lbl">Secrets Found</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('libraries', []))}</div><div class="stat-lbl">Libraries Fingerprinted</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('cves', []))}</div><div class="stat-lbl">Known CVEs</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('technologies', []))}</div><div class="stat-lbl">Technologies</div></div>
    <div class="stat"><div class="stat-num">{sum(len(r['vulnerabilities']) for r in data.get('retire_findings', []))}</div><div class="stat-lbl">retire.js Findings</div></div>
    <div class="stat"><div class="stat-num">{len(data.get('semgrep_findings', []))}</div><div class="stat-lbl">semgrep Findings</div></div>
  </div>

  {section("🔧 Detected Frameworks", fw_html, "#7c3aed")}
  {section("🧩 Technologies (Wappalyzer)", tech_chips, "#7c3aed")}
  {section("📁 Extracted Files", files_html, "#2563eb")}
  {section("🔗 API Endpoints", ep_html, "#0891b2")}
  {section("🔗 LinkFinder Endpoints", lf_chips, "#0891b2")}
  {section("🧭 Routes & Lazy Chunks", route_chips, "#0891b2")}
  {section("🔑 Parameters (Fuzzing Wordlist)", param_chips + wordlist_note, "#059669")}
  {section("⚠️ Potential Secrets / Credentials", sec_html, "#dc2626")}
  {section("🎯 DOM XSS Sinks & postMessage", dom_html, "#dc2626")}
  {section("📦 Library Versions", lib_html, "#0f766e")}
  {section("🛡️ Known CVEs (OSV.dev)", cve_html, "#b91c1c")}
  {section("🛡️ retire.js Findings (local signature scan)", retire_html, "#b91c1c")}
  {section("🧪 semgrep Static Analysis", semgrep_html, "#b45309")}
</div>
</body>
</html>"""

    report_path = out_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path

