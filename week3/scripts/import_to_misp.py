#!/usr/bin/env python3
"""Week 3: import the normalized IOCs into our local MISP.

One MISP event per ransomware family. Hashes, IPs, domains and URLs are
marked for detection (to_ids), file names are only context.
Usage: MISP_KEY=<api key> python3 import_to_misp.py
"""
import csv
import os
import urllib3
from pathlib import Path

from pymisp import MISPEvent, PyMISP

urllib3.disable_warnings()

URL = os.environ.get("MISP_URL", "https://localhost:8443")
KEY = os.environ["MISP_KEY"]
CSV = Path(__file__).resolve().parents[1] / "output" / "iocs_normalized.csv"

misp = PyMISP(URL, KEY, ssl=False)

families = {}
for row in csv.DictReader(CSV.open()):
    families.setdefault(row["family"], []).append(row)

for family, rows in families.items():
    info = f"{family} ransomware IOCs ({rows[0]['source']}) - KZ finance threat hunting project"
    old = misp.search(controller="events", eventinfo=info, pythonify=True)
    if old:
        print(f"skip, already imported: {info}")
        continue
    ev = MISPEvent()
    ev.info = info
    ev.distribution = 0      # your organisation only
    ev.threat_level_id = 1   # high
    ev.analysis = 2          # completed
    ev.add_tag("tlp:clear")
    ev.add_tag(f'misp-galaxy:ransomware="{family}"')
    ev.add_tag("kz-finance-project")
    for r in rows:
        ev.add_attribute(r["type"], r["value"],
                         to_ids=r["type"] != "filename",
                         comment=f"source: {r['source']}")
    res = misp.add_event(ev, pythonify=True)
    print(f"created event {res.id}: {family}, {len(rows)} attributes")
