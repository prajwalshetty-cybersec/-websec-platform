"""
report_generator.py
--------------------
Renders a ScanResult into a self-contained, dark/red "hacker terminal" styled
HTML report.
"""

import html
import json
from scanner import ScanResult

SEVERITY_COLORS = {
    "CRITICAL": "#ff0033",
    "HIGH": "#ff4d4d",
    "MEDIUM": "#ff9900",
    "LOW": "#ffcc00",
    "INFO": "#33ff66",
}

BANNER = r"""
 __        __   _       ____                  ____             
 \ \      / /__| |__   / ___|  ___  ___       / ___|  ___ __ _  
  \ \ /\ / / _ \ '_ \  \___ \ / _ \/ __|_____  \___ \ / __/ _` |
   \ V  V /  __/ |_) |  ___) |  __/ (_|_____|  ___) | (_| (_| |
    \_/\_/ \___|_.__/  |____/ \___|\___|      |____/ \___\__,_|
"""


def _findings_rows(findings):
    rows = []
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "#ffffff")
        rec = f"<div class='rec'>&gt; recommendation: {html.escape(f.recommendation)}</div>" if f.recommendation else ""
        rows.append(f"""
        <tr class="finding-row" data-sev="{f.severity}">
          <td><span class="badge" style="--c:{color}">{f.severity}</span></td>
          <td>{html.escape(f.category)}</td>
          <td>
            <div class="ftitle">{html.escape(f.title)}</div>
            <div class="fdetail">{html.escape(f.detail)}</div>
            {rec}
          </td>
        </tr>""")
    return "\n".join(rows)


def generate_html_report(result: ScanResult) -> str:
    counts = result.counts()
    score = result.score()
    score_color = "#33ff66" if score >= 80 else "#ff9900" if score >= 50 else "#ff0033"

    filter_buttons = "".join(
        f'<button class="filter-btn" data-filter="{sev}" style="--c:{col}">{sev} ({counts.get(sev,0)})</button>'
        for sev, col in SEVERITY_COLORS.items()
    )

    rows_html = _findings_rows(result.findings)

    raw_json = json.dumps(
        {
            "target": result.target,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "score": score,
            "counts": counts,
            "meta": result.meta,
            "findings": [f.__dict__ for f in result.findings],
        },
        indent=2,
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report :: {html.escape(result.target)}</title>
<style>
  :root {{
    --bg: #060707;
    --panel: #0c0f0c;
    --grid: #131a13;
    --red: #ff0033;
    --red-dim: #7a0019;
    --green: #33ff66;
    --text: #c8f7d0;
    --muted: #6b8a72;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', 'Fira Code', monospace;
    margin: 0;
    padding: 0;
  }}
  body {{
    background-image:
      linear-gradient(rgba(255,0,51,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,0,51,0.04) 1px, transparent 1px);
    background-size: 28px 28px;
    min-height: 100vh;
  }}
  body::before {{
    content: "";
    position: fixed; inset: 0;
    pointer-events: none;
    background: repeating-linear-gradient(
      0deg, rgba(255,0,51,0.03) 0px, rgba(255,0,51,0.03) 1px,
      transparent 1px, transparent 3px
    );
    z-index: 999;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 28px 20px 60px; }}
  pre.banner {{
    color: var(--red);
    text-shadow: 0 0 8px rgba(255,0,51,0.85), 0 0 18px rgba(255,0,51,0.4);
    font-size: 10px;
    line-height: 1.1;
    overflow-x: auto;
    margin: 0 0 6px;
  }}
  .subtitle {{
    color: var(--muted);
    letter-spacing: 2px;
    font-size: 12px;
    text-transform: uppercase;
    margin-bottom: 24px;
    border-bottom: 1px dashed var(--red-dim);
    padding-bottom: 14px;
  }}
  .subtitle b {{ color: var(--red); }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 26px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--red-dim);
    border-radius: 4px;
    padding: 14px 16px;
    position: relative;
    overflow: hidden;
  }}
  .card::after {{
    content: "";
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--red), transparent);
  }}
  .card .label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .card .value {{ font-size: 26px; font-weight: bold; margin-top: 4px; }}
  .score-ring {{
    color: {score_color};
    text-shadow: 0 0 10px currentColor;
  }}
  .panel {{
    background: var(--panel);
    border: 1px solid var(--red-dim);
    border-radius: 4px;
    padding: 18px;
    margin-bottom: 20px;
  }}
  .panel h2 {{
    margin: 0 0 14px;
    font-size: 14px;
    color: var(--red);
    text-transform: uppercase;
    letter-spacing: 2px;
    border-left: 3px solid var(--red);
    padding-left: 10px;
  }}
  .filters {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }}
  .filter-btn {{
    background: transparent;
    border: 1px solid var(--c);
    color: var(--c);
    padding: 6px 10px;
    font-family: inherit;
    font-size: 11px;
    border-radius: 3px;
    cursor: pointer;
    letter-spacing: 1px;
  }}
  .filter-btn.active {{ background: var(--c); color: #000; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td {{ padding: 10px 8px; vertical-align: top; border-bottom: 1px solid #131a13; }}
  .badge {{
    display: inline-block;
    border: 1px solid var(--c);
    color: var(--c);
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    letter-spacing: 1px;
    white-space: nowrap;
  }}
  .ftitle {{ color: #fff; font-weight: bold; margin-bottom: 3px; }}
  .fdetail {{ color: var(--text); opacity: 0.85; }}
  .rec {{ color: var(--green); opacity: 0.8; margin-top: 4px; font-size: 12px; }}
  footer {{ color: var(--muted); font-size: 11px; text-align: center; margin-top: 30px; }}
  details summary {{ cursor: pointer; color: var(--muted); font-size: 12px; }}
  pre.json {{
    background: #050505;
    padding: 12px;
    overflow-x: auto;
    font-size: 11px;
    color: var(--green);
    border: 1px solid var(--red-dim);
    border-radius: 4px;
  }}
  ::selection {{ background: var(--red); color: #000; }}
</style>
</head>
<body>
<div class="wrap">
  <pre class="banner">{BANNER}</pre>
  <div class="subtitle">
    AUTOMATED WEB APPLICATION SECURITY ASSESSMENT &amp; REPORTING PLATFORM<br>
    TARGET: <b>{html.escape(result.target)}</b> &nbsp;|&nbsp;
    SCAN START: {html.escape(result.started_at)} &nbsp;|&nbsp;
    SCAN END: {html.escape(result.finished_at)}
  </div>

  <div class="grid">
    <div class="card"><div class="label">Risk Score</div><div class="value score-ring">{score}/100</div></div>
    <div class="card"><div class="label">Critical</div><div class="value" style="color:{SEVERITY_COLORS['CRITICAL']}">{counts['CRITICAL']}</div></div>
    <div class="card"><div class="label">High</div><div class="value" style="color:{SEVERITY_COLORS['HIGH']}">{counts['HIGH']}</div></div>
    <div class="card"><div class="label">Medium</div><div class="value" style="color:{SEVERITY_COLORS['MEDIUM']}">{counts['MEDIUM']}</div></div>
    <div class="card"><div class="label">Low</div><div class="value" style="color:{SEVERITY_COLORS['LOW']}">{counts['LOW']}</div></div>
    <div class="card"><div class="label">Info</div><div class="value" style="color:{SEVERITY_COLORS['INFO']}">{counts['INFO']}</div></div>
  </div>

  <div class="panel">
    <h2>&gt; Findings</h2>
    <div class="filters">
      <button class="filter-btn active" data-filter="ALL" style="--c:#ffffff">ALL</button>
      {filter_buttons}
    </div>
    <table id="findings-table">
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

  <div class="panel">
    <details>
      <summary>&gt; view raw JSON output</summary>
      <pre class="json">{html.escape(raw_json)}</pre>
    </details>
  </div>

  <footer>
    Generated by Automated Web Application Security Assessment &amp; Reporting Platform &mdash;
    for authorized security testing only.
  </footer>
</div>

<script>
  const buttons = document.querySelectorAll('.filter-btn');
  const rows = document.querySelectorAll('.finding-row');
  buttons.forEach(btn => {{
    btn.addEventListener('click', () => {{
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const f = btn.dataset.filter;
      rows.forEach(r => {{
        r.style.display = (f === 'ALL' || r.dataset.sev === f) ? '' : 'none';
      }});
    }});
  }});
</script>
</body>
</html>
"""
