#!/usr/bin/env python3
"""Week 2: draw simple bar charts (SVG) from ransomware_stats.json."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
stats = json.loads((ROOT / "output" / "ransomware_stats.json").read_text())
IMG = ROOT / "images"
IMG.mkdir(exist_ok=True)


def bar_chart(title, items, path, color="#3b6fb6"):
    w, bar_h, gap, left, top = 640, 24, 8, 150, 40
    h = top + len(items) * (bar_h + gap) + 20
    mx = max(v for _, v in items)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
           f'font-family="Arial" font-size="13">',
           f'<rect width="{w}" height="{h}" fill="white"/>',
           f'<text x="10" y="24" font-size="16" font-weight="bold">{title}</text>']
    for i, (label, v) in enumerate(items):
        y = top + i * (bar_h + gap)
        bw = (w - left - 60) * v / mx
        out.append(f'<text x="{left - 8}" y="{y + 17}" text-anchor="end">{label}</text>')
        out.append(f'<rect x="{left}" y="{y}" width="{bw:.0f}" height="{bar_h}" fill="{color}"/>')
        out.append(f'<text x="{left + bw + 6:.0f}" y="{y + 17}">{v}</text>')
    out.append("</svg>")
    path.write_text("\n".join(out))
    print("saved", path)


bar_chart("Top ransomware groups attacking the financial sector",
          stats["top_groups_financial"], IMG / "top_groups_financial.svg")
bar_chart("Financial sector ransomware victims by year",
          [(y, n) for y, n in stats["financial_by_year"] if y >= "2020"],
          IMG / "financial_by_year.svg", color="#c0504d")
