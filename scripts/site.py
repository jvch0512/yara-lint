#!/usr/bin/env python3
"""Renders the demo page from a tool's --tsv output.
usage: site.py SAMPLE.tsv OUT.html "Title" "Tagline" "Footnote"
TSV: optional first line '# summary', then SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE rows. The page is static, escaped, CSP 'none'."""
import sys, html

src, out, title, tagline, note = sys.argv[1:6]
summary, rows = "", []
for line in open(src, encoding="utf-8").read().splitlines():
    if line.startswith("#"):
        summary = line.lstrip("# ").strip()
    elif line.strip():
        p = line.split("\t", 3) + [""] * 4
        rows.append(p[:4])
order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
rows.sort(key=lambda r: order.get(r[0].lower(), 9))
e = html.escape
body = "".join(f'<tr><td class="{e(s.lower())}">{e(s.lower())}</td><td>{e(r)}</td><td>{e(w)}</td><td>{e(m)}</td></tr>' for s, r, w, m in rows)
page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>{e(title)}</title><style>:root{{color-scheme:dark}}body{{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}}h1{{margin:0 0 4px}}.sub{{color:#8b98a8}}table{{border-collapse:collapse;width:100%;margin-top:14px}}th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}}th{{color:#8b98a8}}.critical{{color:#f85149;font-weight:700}}.high{{color:#f0883e;font-weight:700}}.medium{{color:#e3b341;font-weight:700}}.low{{color:#58a6ff;font-weight:700}}.info{{color:#8b98a8}}</style></head><body><h1>{e(title)}</h1><p class="sub">{e(tagline)}</p><p>{e(summary)}</p><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>Finding</th></tr>{body}</table><p class="sub">{e(note)} This page is rendered from the tool's --tsv output by scripts/site.py.</p></body></html>
"""
open(out, "w", encoding="utf-8").write(page)
