#!/usr/bin/env python3
"""Week 3: filter and normalize IOCs collected in week 2.

Reads CISA STIX 2.1 bundles, pulls out the indicators, cleans them up
and writes one CSV with a single row per unique IOC.
"""
import csv
import ipaddress
import json
import re
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parents[2] / "week2" / "data" / "cisa"
OUT = Path(__file__).resolve().parents[1] / "output"

SOURCES = {
    "akira_AA24-109A.json": ("Akira", "CISA AA24-109A"),
    "lockbit_AA23-325A.json": ("LockBit 3.0", "CISA AA23-325A"),
    "clop_AA23-158A.json": ("Clop", "CISA AA23-158A"),
}

# STIX pattern pieces like:  file:hashes.'SHA-256' = 'ABC...'   ipv4-addr:value = '1.2.3.4'
PATTERN = re.compile(r"([\w-]+):([\w.'\-]+)\s*=\s*'([^']+)'")

HEX = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(v):
    return (v.replace("[.]", ".").replace("(.)", ".")
             .replace("hxxp", "http").replace("[:]", ":"))


def classify(obj, prop, value):
    """Return (misp_type, normalized_value) or None if we don't keep it."""
    value = refang(value.strip())
    if obj == "file" and "hashes" in prop:
        v = value.lower()
        if re.fullmatch(r"[0-9a-f]+", v) and len(v) in HEX:
            return HEX[len(v)], v
        return None  # ssdeep and others are skipped
    if obj == "file" and prop == "name":
        return "filename", value
    if obj in ("ipv4-addr", "ipv6-addr"):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return None
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return None  # useless for hunting outside the victim network
        return "ip-dst", str(ip)
    if obj == "domain-name":
        return "domain", value.lower().rstrip(".")
    if obj == "url":
        return "url", value
    if obj == "email-addr":
        return "email-src", value.lower()
    return None


def main():
    rows, seen, skipped = [], set(), 0
    for fname, (family, source) in SOURCES.items():
        bundle = json.loads((DATA / fname).read_text())
        for o in bundle.get("objects", []):
            if o.get("type") != "indicator":
                continue
            for obj, prop, val in PATTERN.findall(o.get("pattern", "")):
                res = classify(obj, prop, val)
                if not res:
                    skipped += 1
                    continue
                t, v = res
                if (t, v) in seen:
                    continue  # duplicate across or inside reports
                seen.add((t, v))
                rows.append({"type": t, "value": v, "family": family,
                             "source": source,
                             "first_seen": o.get("created", "")[:10]})
    OUT.mkdir(exist_ok=True)
    out = OUT / "iocs_normalized.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["family"], r["type"])))
    print(f"kept {len(rows)} unique IOCs, skipped {skipped} -> {out}")
    by = {}
    for r in rows:
        by.setdefault((r["family"], r["type"]), 0)
        by[(r["family"], r["type"])] += 1
    for (fam, t), n in sorted(by.items()):
        print(f"  {fam:12} {t:9} {n}")


if __name__ == "__main__":
    sys.exit(main())
