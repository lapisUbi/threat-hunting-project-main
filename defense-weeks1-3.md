# Defense plan, weeks 1-3 (7-8 minutes)

| Time | Part | Show | Say |
|------|------|------|-----|
| 0:00-0:45 | Intro | main README | Our topic is ransomware threats to Kazakhstan's financial sector. Every week I apply the course topic to it. |
| 0:45-2:00 | Week 1 | `week1/glossary.md`, `week1/threat-classification.md` | Glossary of 28 CTI terms with examples from the topic, and a classification of threats by actor, attack type and source. The focus is ransomware groups that go after money. |
| 2:00-4:15 | Week 2 | `week2/README.md` (source table, 2 charts, Shodan table) | Map of open and closed sources. ransomware.live: 1823 victims in finance, top groups Qilin, LockBit, Akira, Clop, and the number grows every year. 3 victims in KZ. Shodan: more than half of LockBit IPs from 2023 are dead, IP IOCs get old fast. VirusTotal and Maltego need registration, so I used free sources. |
| 4:15-6:45 | Week 3 | MISP in the browser, `normalize_iocs.py`, output of `misp_filter.py` | MISP runs in podman. The script took 3 CISA reports, removed duplicates and private IPs, made hashes lower case: 259 IOCs. Imported as 3 events with TLP and ransomware tags. Then filters: only network IOCs, only Akira hashes, a blocklist for a firewall. |
| 6:45-7:30 | Summary | README table | Weeks 1-3 are the first steps of the intelligence lifecycle: direction, collection, processing. Next week: Cyber Kill Chain for these groups. |

Possible questions:
- Why these three groups? They are in the top 4 for finance and CISA has official IOCs for them.
- Why normalize? The same hash can be in upper and lower case, one IOC can be in two reports. Without cleaning MISP gets duplicates and bad correlations.
- Why are some IOCs not for IDS? A file name alone gives too many false positives, it's only context.
- What does TLP:CLEAR mean? The data is public (from CISA) so it can be shared freely.
