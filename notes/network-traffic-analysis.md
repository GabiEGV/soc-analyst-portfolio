# Network Traffic Analysis — Study Notes

TryHackMe SOC Level 1 · Network Traffic Analysis module (5 rooms) · Completed September 2026

## 1. Why network traffic analysis
- What NTA is and where it sits in SOC work (detection, investigation, forensics)
- Full packet capture vs flow data (NetFlow): what each gives you, what it costs
- Tools by job: Wireshark, tcpdump, NetworkMiner, Zeek/Suricata

## 2. Wireshark — the basics
- The three panes: packet list, packet details, packet bytes
- Dissection by layer: Frame → Ethernet → IP → TCP/UDP → application
- Opening PCAPs, coloring rules, custom columns, marking packets

## 3. Packet operations
- Capture filters vs display filters
- Display filters I use most (8–10, one line each)
- Statistics: Conversations, Endpoints, Protocol Hierarchy
- Follow TCP/UDP stream · Export Objects

## 4. Traffic analysis — what each attack looks like
- Nmap scans: SYN vs TCP connect vs UDP
- ARP poisoning / MITM
- Host identification: DHCP, NetBIOS, Kerberos
- DNS tunneling · ICMP tunneling
- Cleartext credentials: FTP, HTTP
- Decrypting HTTPS with a TLS key log file

## 5. NetworkMiner
- Passive analysis of a PCAP
- Hosts, Files, Credentials, Sessions tabs
- When it beats Wireshark and when it doesn't

## Key takeaways
- 3–5 bullets: what changed in how I'd triage a network alert