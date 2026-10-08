# Week 1 - Glossary of CTI terms

Topic: ransomware threats to the financial sector of Kazakhstan.
Next to every term I wrote a small example from our topic, so it's easier to remember.

| # | Term | Meaning | Example |
|---|------|---------|---------|
| 1 | CTI (Cyber Threat Intelligence) | Information about threats that is collected and analyzed to make security decisions | knowing that Qilin attacks banks more than other groups |
| 2 | Threat | Anything that can harm a system or a company | a ransomware gang that wants to encrypt a bank's servers |
| 3 | Threat actor | Person or group behind an attack | LockBit, Akira, Clop |
| 4 | Vulnerability | A weakness an attacker can use | CVE-2023-4966 (Citrix Bleed), used by LockBit affiliates |
| 5 | Risk | Threat x vulnerability x impact, basically how likely and how bad an attack is | unpatched VPN in a bank = high risk |
| 6 | IOC (Indicator of Compromise) | Technical sign that an attack happened: hash, IP, domain, URL, file name | SHA-256 of an Akira encryptor |
| 7 | IOA (Indicator of Attack) | Sign that an attack is going on right now, based on behavior | lots of files renamed to a new extension in a few minutes |
| 8 | TTP (Tactics, Techniques, Procedures) | How the attacker works: the goal, the method and the exact steps | T1486 Data Encrypted for Impact |
| 9 | APT (Advanced Persistent Threat) | Skilled and well-funded actor that stays in a network for a long time | state groups that go after central banks |
| 10 | Ransomware | Malware that encrypts data and asks money for the key | LockBit 3.0 |
| 11 | Double extortion | Data is stolen before encryption and the gang threatens to leak it | victim names on a leak site |
| 12 | RaaS (Ransomware-as-a-Service) | Developers rent their ransomware to "affiliates" and take a percent | LockBit, Qilin, Akira |
| 13 | Initial Access Broker | Criminal who sells access to already hacked networks | selling a bank's VPN login to an affiliate |
| 14 | Strategic intelligence | High-level info for management: trends, risks, money | "attacks on finance grew in 2025" |
| 15 | Operational intelligence | Info about specific campaigns and actors | "Clop mass-exploits MOVEit" |
| 16 | Tactical intelligence | Info about TTPs for the SOC | detection rule for `vssadmin delete shadows` |
| 17 | Technical intelligence | Concrete IOCs to block | list of LockBit IPs for the firewall |
| 18 | Intelligence lifecycle | Direction, Collection, Processing, Analysis, Dissemination, Feedback | weeks 1-3 cover the first three steps |
| 19 | OSINT | Intelligence from open sources | ransomware.live, CISA advisories |
| 20 | TLP (Traffic Light Protocol) | Labels that show how widely info can be shared: RED, AMBER, GREEN, CLEAR | our IOCs are public so TLP:CLEAR |
| 21 | STIX / TAXII | STIX is a format for threat data, TAXII is a protocol to share it | CISA gives IOCs as STIX 2.1 JSON |
| 22 | MISP | Open-source platform to store and share threat intel | used in week 3 |
| 23 | Cyber Kill Chain | Lockheed Martin model with 7 attack stages | from recon up to encryption |
| 24 | MITRE ATT&CK | Knowledge base of real attacker tactics and techniques | describing how ransomware works |
| 25 | Threat hunting | Looking for attackers who are already inside before any alert | searching bank logs for Akira traces |
| 26 | False positive | Alert that looks bad but is normal | admin running a backup script |
| 27 | Pyramid of Pain | Blocking TTPs hurts attackers more than blocking hashes or IPs | a hash is easy to change, a TTP is not |
| 28 | Enrichment | Adding context to raw data (geo, owner, reputation) | checking a LockBit IP in Shodan |
