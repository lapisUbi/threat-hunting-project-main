#!/usr/bin/env python3
"""Week 2: OSINT data collection for our topic
(ransomware threats to the financial sector of Kazakhstan).

1. ransomware.live  - which groups attack the financial sector, and Kazakhstan
2. Shodan InternetDB - what Shodan already knows about LockBit IPs (no API key needed)
Results are saved as aggregated JSON (no victim names are stored in the repo).
"""
import collections
import csv
import json
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "output"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "student-cti-project"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def ransomware_stats():
    fin = get("https://api.ransomware.live/v2/sectorvictims/Financial%20Services")
    kz = get("https://api.ransomware.live/v2/countryvictims/KZ")
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / "financial_victims.json").write_text(json.dumps(fin))
    (RAW / "kz_victims.json").write_text(json.dumps(kz))

    groups = collections.Counter(v.get("group") for v in fin)
    years = collections.Counter((v.get("discovered") or "")[:4] for v in fin)
    countries = collections.Counter(v.get("country") or "unknown" for v in fin)
    return {
        "financial_sector_total": len(fin),
        "top_groups_financial": groups.most_common(10),
        "financial_by_year": sorted(years.items()),
        "top_countries_financial": countries.most_common(10),
        "kazakhstan_total": len(kz),
        "kazakhstan_by_group": collections.Counter(v.get("group_name") for v in kz).most_common(),
        "kazakhstan_by_sector": collections.Counter(v.get("activity") for v in kz).most_common(),
    }


def shodan_internetdb():
    ioc_csv = ROOT.parent / "week3" / "output" / "iocs_normalized.csv"
    ips = [r["value"] for r in csv.DictReader(ioc_csv.open()) if r["type"] == "ip-dst"]
    result = []
    for ip in ips:
        try:
            d = get(f"https://internetdb.shodan.io/{ip}")
        except Exception:
            d = {"ip": ip, "note": "no data in Shodan"}
        result.append(d)
        time.sleep(1)
    return result


def main():
    OUT.mkdir(exist_ok=True)
    stats = ransomware_stats()
    (OUT / "ransomware_stats.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps(stats, indent=2))
    shodan = shodan_internetdb()
    (OUT / "shodan_internetdb.json").write_text(json.dumps(shodan, indent=2))
    for d in shodan:
        print(d.get("ip"), d.get("ports", "-"), d.get("vulns", [])[:3], d.get("note", ""))


if __name__ == "__main__":
    main()
