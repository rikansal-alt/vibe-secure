"""Render scan results."""
from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime, timezone

_C = {"HIGH": "\033[0;31m", "MEDIUM": "\033[0;33m", "LOW": "\033[0;36m",
      "INFO": "\033[0;34m", "ok": "\033[0;32m", "dim": "\033[2m",
      "bold": "\033[1m", "reset": "\033[0m"}


def _color():
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(k, t):
    return f"{_C.get(k,'')}{t}{_C['reset']}" if _color() else t


def render_text(result) -> str:
    out = [f"{_c('dim','stack:')} {result.stack.label()}   "
           f"{_c('dim','files:')} {result.files_scanned}", ""]
    buckets = result.by_severity()
    any_f = False
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        items = buckets[sev]
        if not items:
            continue
        any_f = True
        out.append(_c(sev, f"{sev}  ({len(items)})"))
        for f in items:
            tag = _c("bold", "[agent] ") if f.category == "agent" else f"[{f.category}] "
            out.append(f"  • {tag}{f.message}")
            loc = f"{f.path}:{f.line}" if f.path and f.line else f.path
            if loc:
                out.append(_c("dim", f"      {loc}"))
            if f.snippet:
                out.append(_c("dim", f"      {f.snippet}"))
        out.append("")
    if not any_f:
        out.append(_c("ok", "No findings."))
    if result.notes:
        out.append(_c("dim", "notes:"))
        out += [_c("dim", f"  - {n}") for n in result.notes]
        out.append("")
    ac = result.agent_count
    if result.high_count:
        out.append(_c("HIGH", f"{result.high_count} high-severity finding(s). Fix before shipping."))
    elif any_f:
        out.append(_c("MEDIUM", "No high-severity findings, but review the items above."))
    else:
        out.append(_c("ok", "Clean."))
    if ac:
        out.append(_c("dim", f"({ac} of these are agent-layer findings — the part other scanners miss.)"))
    return "\n".join(out)


def render_json(result) -> str:
    return json.dumps({
        "stack": sorted(result.stack.stacks),
        "agents": sorted(result.stack.agents),
        "files_scanned": result.files_scanned,
        "high_count": result.high_count,
        "agent_count": result.agent_count,
        "findings": [{"severity": f.severity, "category": f.category,
                      "message": f.message, "path": f.path, "line": f.line,
                      "snippet": f.snippet} for f in result.findings],
        "notes": result.notes,
    }, indent=2)


_SEV_META = {
    "HIGH":   ("#ef4444", "Fix before shipping"),
    "MEDIUM": ("#f59e0b", "Worth a review"),
    "LOW":    ("#38bdf8", "Cheap hardening"),
    "INFO":   ("#818cf8", "For your awareness"),
}


def _e(t) -> str:
    return html.escape(str(t), quote=True)


def render_html(result, root=None) -> str:
    """Self-contained, theme-aware HTML report — no external assets."""
    buckets = result.by_severity()
    title = _e(root) if root else "scan"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if result.high_count:
        verdict_cls, verdict = "bad", f"{result.high_count} high-severity finding(s) — fix before shipping."
    elif any(buckets[s] for s in buckets):
        verdict_cls, verdict = "warn", "No high-severity findings, but review the items below."
    else:
        verdict_cls, verdict = "good", "Clean — no findings."

    tiles = []
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        color, _ = _SEV_META[sev]
        tiles.append(
            f'<div class="tile"><span class="dot" style="background:{color}"></span>'
            f'<span class="num">{len(buckets[sev])}</span>'
            f'<span class="lbl">{sev.title()}</span></div>')

    sections = []
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        items = buckets[sev]
        if not items:
            continue
        color, blurb = _SEV_META[sev]
        rows = []
        for f in items:
            agent = '<span class="badge agent">agent-layer</span>' if f.category == "agent" else ""
            cat = f'<span class="badge">{_e(f.category)}</span>'
            loc = f"{f.path}:{f.line}" if f.path and f.line else (f.path or "")
            loc_html = f'<div class="loc">{_e(loc)}</div>' if loc else ""
            snip = f'<pre class="snip">{_e(f.snippet)}</pre>' if f.snippet else ""
            rows.append(
                f'<li class="finding">{cat}{agent}'
                f'<div class="msg">{_e(f.message)}</div>{loc_html}{snip}</li>')
        sections.append(
            f'<section class="sev"><h2 style="--sev:{color}">{sev.title()} '
            f'<span class="count">{len(items)}</span><span class="blurb">{blurb}</span></h2>'
            f'<ul class="findings">{"".join(rows)}</ul></section>')

    notes = ""
    if result.notes:
        lis = "".join(f"<li>{_e(n)}</li>" for n in result.notes)
        notes = f'<section class="notes"><h3>Notes</h3><ul>{lis}</ul></section>'

    ac = result.agent_count
    agent_line = (f'<p class="agentline">{ac} of these are '
                  f'<strong>agent-layer</strong> findings — the part other scanners miss.</p>'
                  if ac else "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibe-secure · {title}</title>
<style>
:root {{
  --bg:#f7f7f8; --card:#fff; --ink:#18181b; --muted:#71717a; --line:#e4e4e7;
  --good:#22c55e; --warn:#f59e0b; --bad:#ef4444;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0b0b0d; --card:#161619; --ink:#f4f4f5; --muted:#a1a1aa; --line:#27272a; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
.wrap {{ max-width:860px; margin:0 auto; padding:40px 20px 80px; }}
header .brand {{ font-weight:700; letter-spacing:-.01em; }}
header .brand span {{ color:var(--muted); font-weight:500; }}
h1 {{ margin:.2em 0 .1em; font-size:1.9rem; letter-spacing:-.02em; word-break:break-word; }}
.meta {{ color:var(--muted); font-size:.9rem; margin-bottom:22px; }}
.meta code {{ background:var(--card); border:1px solid var(--line); border-radius:5px; padding:1px 6px; }}
.verdict {{ border-radius:12px; padding:14px 18px; font-weight:600; margin:0 0 26px; border:1px solid var(--line); }}
.verdict.good {{ background:color-mix(in srgb,var(--good) 12%,var(--card)); }}
.verdict.warn {{ background:color-mix(in srgb,var(--warn) 14%,var(--card)); }}
.verdict.bad  {{ background:color-mix(in srgb,var(--bad) 14%,var(--card)); }}
.tiles {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:30px; }}
.tile {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px;
  display:flex; flex-direction:column; gap:4px; }}
.tile .dot {{ width:10px; height:10px; border-radius:50%; }}
.tile .num {{ font-size:1.8rem; font-weight:700; line-height:1; }}
.tile .lbl {{ color:var(--muted); font-size:.82rem; text-transform:uppercase; letter-spacing:.04em; }}
.sev h2 {{ font-size:1.05rem; margin:30px 0 12px; display:flex; align-items:center; gap:10px;
  padding-left:12px; border-left:4px solid var(--sev); }}
.sev h2 .count {{ background:var(--sev); color:#fff; border-radius:20px; font-size:.75rem;
  padding:2px 9px; font-weight:700; }}
.sev h2 .blurb {{ color:var(--muted); font-weight:400; font-size:.85rem; margin-left:auto; }}
.findings {{ list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:10px; }}
.finding {{ background:var(--card); border:1px solid var(--line); border-radius:11px; padding:14px 16px; }}
.badge {{ display:inline-block; font-size:.72rem; font-weight:600; text-transform:uppercase;
  letter-spacing:.03em; color:var(--muted); background:color-mix(in srgb,var(--muted) 14%,transparent);
  border-radius:6px; padding:2px 7px; margin-right:6px; }}
.badge.agent {{ color:#fff; background:#7c3aed; }}
.finding .msg {{ margin-top:8px; font-weight:500; }}
.loc {{ color:var(--muted); font-size:.85rem; margin-top:4px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
.snip {{ margin:8px 0 0; padding:9px 11px; background:var(--bg); border:1px solid var(--line);
  border-radius:8px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.82rem;
  overflow-x:auto; white-space:pre; }}
.notes {{ margin-top:34px; }}
.notes h3 {{ font-size:.95rem; }}
.notes ul {{ color:var(--muted); }}
.agentline {{ margin-top:26px; padding-top:18px; border-top:1px solid var(--line); color:var(--muted); font-size:.9rem; }}
.agentline strong {{ color:#7c3aed; }}
footer {{ margin-top:40px; color:var(--muted); font-size:.8rem; text-align:center; }}
@media (max-width:560px) {{ .tiles {{ grid-template-columns:repeat(2,1fr); }} }}
</style></head>
<body><div class="wrap">
<header><div class="brand">vibe-secure <span>· security report</span></div>
<h1>{title}</h1>
<p class="meta">Stack <code>{_e(result.stack.label())}</code> &nbsp;·&nbsp; {result.files_scanned} files &nbsp;·&nbsp; {stamp}</p></header>
<div class="verdict {verdict_cls}">{_e(verdict)}</div>
<div class="tiles">{"".join(tiles)}</div>
{"".join(sections)}
{notes}
{agent_line}
<footer>Generated by vibe-secure — it scans your app <em>and</em> the agent that built it.</footer>
</div></body></html>"""
