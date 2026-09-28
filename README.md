# SOC Analyst Portfolio — Gabriel García Villegas

Entry-level SOC Analyst candidate based in Buenos Aires, Argentina, with EU work authorization (Spanish citizenship). This repository documents my hands-on training and practical case analysis as I work toward CompTIA Security+ and BTL1 certifications, following the TryHackMe SOC Level 1 learning path.

Tools & Technologies: Splunk • Sysmon • MITRE ATT&CK • Sigma • CyberChef • VirusTotal • DNS • Windows Event Logs • Wireshark • NetworkMiner.

## 🚨 Featured SOC Investigations

[Phishing Unfolding — DNS Tunneling Exfiltration Incident](tryhackme/phishing-unfolding.md)

Live SOC simulator exercise (Splunk) where I triaged and correlated 10+ alerts spread across email and endpoint telemetry into a single incident: a phishing email led to execution, unauthorized access to a financial records share, anti-forensic cleanup, and active data exfiltration via DNS tunneling. Full attack chain reconstruction, MITRE ATT&CK mapping, and IOCs documented.

[The Greenholt Phish — Email Header & Infrastructure Analysis](tryhackme/greenholt-phish.md)

Full header analysis of a spoofed phishing email: SPF/DMARC verification, sending infrastructure investigation (WHOIS), and identification of a disguised malicious attachment via file signature analysis.

## 📁 Repository Structure

| Folder | Contents |
|---|---|
| `tryhackme/` | Room writeups from the TryHackMe SOC Level 1 path — email/phishing analysis, network traffic analysis, SOC simulator incidents, and more as they're completed |
| `labs/` | Hands-on lab work outside of TryHackMe rooms |
| `sigma-rules/` | Custom Sigma detection rules written for practice scenarios |
| `notes/` | Structured study notes (SIEM, MITRE ATT&CK, networking fundamentals, etc.) |
| `writeups/` | Case writeups and incident analysis practice |

## 🛠 Tools & Skills Practiced

- SIEM: Splunk (alert triage, log correlation)
- Analysis: Sysmon, CyberChef, VirusTotal, urlscan.io, Cisco Talos, WHOIS/DNS lookups (SPF, DMARC)
- Frameworks: MITRE ATT&CK, Cyber Kill Chain, Pyramid of Pain
- Detection Engineering: 3 custom Sigma rules mapped to MITRE ATT&CK (SPF spoofing, brute force, DNS tunneling)
- Networking: Subnetting, DNS, TCP/UDP fundamentals
- Network traffic analysis: Wireshark (display filters, protocol dissection, tunneling and cleartext credential detection), NetworkMiner

## 📜 Current Learning

- TryHackMe SOC Level 1 Path (ongoing)
- CompTIA Security+
- BTL1 (Blue Team Level 1)

## 📫 Contact

[LinkedIn](https://www.linkedin.com/in/gabriel-garcia-villegas/) 

---
*This portfolio is actively updated as I progress through my SOC Level 1 training.*
