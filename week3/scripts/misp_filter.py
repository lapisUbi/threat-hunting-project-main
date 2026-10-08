#!/usr/bin/env python3
"""Week 3: filtering examples on data stored in MISP (restSearch API).

Each query answers one simple question a hunter might ask.
Usage: MISP_KEY=<api key> python3 misp_filter.py
"""
import os
import urllib3

from pymisp import PyMISP

urllib3.disable_warnings()
misp = PyMISP(os.environ.get("MISP_URL", "https://localhost:8443"),
              os.environ["MISP_KEY"], ssl=False)

queries = {
    "All network IOCs (IPs, domains, URLs) to block": dict(
        type_attribute=["ip-dst", "domain", "url"], to_ids=True, tags=["kz-finance-project"]),
    "SHA-256 hashes of Akira files (for EDR)": dict(
        type_attribute="sha256", tags=['misp-galaxy:ransomware="Akira"']),
    "Everything from the Clop MOVEit report": dict(
        tags=['misp-galaxy:ransomware="Clop"']),
    "Only detection IOCs, file names excluded": dict(
        to_ids=True, tags=["kz-finance-project"]),
}

for title, q in queries.items():
    attrs = misp.search(controller="attributes", pythonify=True, **q)
    print(f"\n== {title}: {len(attrs)} results")
    for a in attrs[:5]:
        print(f"   {a.type:8} {a.value}")
    if len(attrs) > 5:
        print("   ...")

# export for a firewall: plain text list of IPs
ips = misp.search(controller="attributes", type_attribute="ip-dst",
                  to_ids=True, pythonify=True)
blocklist = sorted({a.value for a in ips})
print(f"\n== Firewall blocklist: {len(blocklist)} IPs")
print("\n".join(blocklist))
