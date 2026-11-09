# SOC Analyst Portfolio — Gabriel García Villegas

Entry-level SOC Analyst candidate based in Buenos Aires, Argentina, with EU work authorization (Spanish citizenship). This repository documents my hands-on training and practical case analysis as I work toward CompTIA Security+ and BTL1 certifications, following the TryHackMe SOC Level 1 learning path.

Tools & Technologies: Splunk • Wireshark • Snort • Zeek • Kibana • Sysmon • MITRE ATT&CK • Sigma • CyberChef • VirusTotal • DNS • Windows Event Logs • NetworkMiner

## Featured investigations

[Initech Perimeter Breach — Firewall, IDS and VPN Log Correlation](tryhackme/network-security-essentials.md)

One month of perimeter logs from three sources, investigated in Splunk. Starting from the external IP with the most firewall blocks, I pivoted through the VPN log (118 password guesses against a service account, then a success and an assigned internal IP), back to the firewall (that IP probing three internal hosts over SMB, RDP and SSH), and into the IDS alerts (a workstation beaconing to port 4444 every six hours, then large HTTP uploads). Timeline, MITRE ATT&CK mapping, IOCs and containment steps documented.

[Wireshark: Traffic Analysis — ARP Poisoning and Man-in-the-Middle](tryhackme/wireshark-traffic-analysis.md)

Packet capture investigation: two MACs answering for the gateway's IP, an ARP request flood scanning the whole subnet from the same MAC, and HTTP traffic between the victim and the internet going through the attacker in both directions. Identified the attacker, confirmed the MITM position with MAC-level evidence, mapped it to MITRE ATT&CK and listed what I would do next in a real SOC. Five captures included.

[Phishing Unfolding — DNS Tunneling Exfiltration Incident](tryhackme/phishing-unfolding.md)

Live SOC simulator exercise (Splunk) where I triaged and correlated 10+ alerts spread across email and endpoint telemetry into a single incident: a phishing email led to execution, unauthorized access to a financial records share, anti-forensic cleanup, and active data exfiltration via DNS tunneling. Full attack chain reconstruction, MITRE ATT&CK mapping, and IOCs documented.

[The Greenholt Phish — Email Header & Infrastructure Analysis](tryhackme/greenholt-phish.md)

Full header analysis of a spoofed phishing email: SPF/DMARC verification, sending infrastructure investigation (WHOIS), and identification of a disguised malicious attachment via file signature analysis.

## Repository structure

| Folder | Contents |
|---|---|
| `tryhackme/` | Room writeups from the TryHackMe SOC Level 1 path — email/phishing analysis, network traffic analysis, network security monitoring, SOC simulator incidents, and more as they're completed |
| `labs/` | Hands-on lab work outside of TryHackMe rooms |
| `sigma-rules/` | Custom Sigma detection rules written for practice scenarios |
| `notes/` | Structured study notes (network traffic analysis, network security monitoring, SIEM, MITRE ATT&CK, etc.) |
| `writeups/` | Case writeups and incident analysis practice |

## Tools and skills

- SIEM: Splunk (alert triage, log correlation across firewall, IDS and VPN sources), Kibana (Zeek connection logs)
- Analysis: Sysmon, CyberChef, VirusTotal, urlscan.io, Cisco Talos, WHOIS/DNS lookups (SPF, DMARC)
- Frameworks: MITRE ATT&CK, Cyber Kill Chain, Pyramid of Pain
- Detection Engineering: 3 custom Sigma rules mapped to MITRE ATT&CK (SPF spoofing, brute force, DNS tunneling)
- Networking: Subnetting, DNS, TCP/UDP fundamentals
- Network traffic analysis: Wireshark (display filters, protocol dissection, tunneling and cleartext credential detection), NetworkMiner
- Network security monitoring: Snort (IDS/IPS modes, writing rules), detecting port scans, DNS/ICMP exfiltration and ARP poisoning in network traffic

## Current learning

- TryHackMe SOC Level 1 Path (7 of 14 modules completed)
- CompTIA Security+ SY0-701 (in preparation)
- BTL1 (Blue Team Level 1)

## Contact

[LinkedIn](https://www.linkedin.com/in/gabriel-garcia-villegas/)
