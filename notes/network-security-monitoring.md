# Network Security Monitoring — Study Notes

TryHackMe SOC Level 1 · Network Security Monitoring module (6 rooms) · Completed November 2026

Working notes from the module. Same idea as the [traffic analysis notes](network-traffic-analysis.md): I kept what I expect to reach for again when a network alert comes in, plus the questions I had to stop and work out. The full investigation from the first room is written up separately in [Network Security Essentials — Initech Perimeter Breach](../tryhackme/network-security-essentials.md).

## 1. Network security essentials

**Why network logs matter even with an EDR on every host.** Malware can hide well inside a machine, but to do anything useful it has to talk to its server, and that conversation leaves through the network. The module's line that stuck with me: endpoint logs may reveal the malicious process, but network logs usually show the C2 first.

**Two meanings of "gateway" I kept mixing.** The network gateway is the device that routes traffic out of the local network (the router, 192.168.1.1 at home). The security gateway is the mandatory checkpoint everything passes through to be filtered (the firewall). Both are roles, not boxes; a home router does both, and so does an NGFW.

**Host logs vs network logs.** Host logs say what happened inside the room; network logs say who entered and left the building. Routers and switches don't log events, they export flow data: one line per conversation (who, with whom, how long, how many bytes), no content. Light enough to keep for months, and enough to spot beaconing and large transfers, because those patterns live in volume and regularity, not in content.

**The grid I use to place any tool.** Two questions: does it look at the network or the host, and does it record everything or only judge?

```
                 LOOKS AT       PRODUCES        EXAMPLES
network, records traffic        logs of all     Zeek, firewall, proxy, flow data
network, judges  traffic        alerts          IDS/IPS: Snort, Suricata (also inside NGFWs)
host, records    the machine    logs of all     Windows Event Logs, syslog, Sysmon
host, judges     the machine    alerts          EDR (CrowdStrike, Defender, SentinelOne), AV, HIDS

Wireshark        traffic        packets         not permanent; I open it for the fine detail
Security Onion   traffic        several         a box that ships Zeek + Suricata + Wireshark
NGFW             traffic        several         one appliance doing firewall + IPS + proxy
SIEM             everything     correlation     receives all of the above and crosses them
```

**Perimeter.** Firewall, router, DMZ (public servers: web, mail, VPN) and the VPN gateway. The TAP for the sensor goes *before* the firewall, not after: that way you also capture what the firewall drops, which tells you what is being attempted. After the firewall you only see what got through.

**The three patterns that separate noise from an attack:**

```
one source → many destinations          scanning
one source → one destination, repeated  brute force
perfect, regular intervals              beaconing
```

**Firewall vs IDS vs VPN log.** Each is written by a different device, records a different thing and answers a different question. The firewall records every connection with ALLOW/BLOCK but doesn't judge it: "who talked to whom, and did it pass". The IDS writes only when a signature matches, so it has fewer lines and each one comes with a diagnosis (ET = Emerging Threats ruleset; TROJAN and EXPLOIT are serious, INFO is informational): "what attack was it". The VPN log records authentications only, with the internal IP assigned on success: "who got in and what seat did they take". An investigation is a chain of pivots between the three.

Counting frequencies in a raw log, the same thing stats count by does in Splunk, but by hand:
```
cat firewall.log | grep "BLOCK" | cut -d' ' -f5 | cut -d: -f1 | sort | uniq -c | sort -nr
```

Fields in cut count from 1, not 0. sort before uniq -c is mandatory, because uniq only collapses adjacent duplicates: without it, an IP that shows up on lines 1, 50 and 200 gets counted as three separate 1s instead of one 3. The output looks fine, the numbers are just wrong.

## 2. Network discovery detection

**External vs internal scan, and why it changes everything.** Public IP → company IP is Reconnaissance in ATT&CK terms: the attacker is outside, severity is low, you block the IP knowing they'll be back from another one. Private IP → private IP is Discovery: the attacker is already in and mapping where to move next. Severity is high, and blocking the source IP is not a fix, for three reasons: traffic inside a segment never touches the firewall, the host is still compromised, and if you don't find how they got in, they get in again.

**Horizontal vs vertical.** Horizontal is one port across many hosts ("who has 445 open?"). Vertical is many ports on one host ("what does 10.0.0.20 run?"). In a log: many destinations with one connection each is horizontal; one destination with thousands is vertical.

**Things I had to sort out about scans.** TCP and UDP each have their own 0–65535 port space, so 53/tcp and 53/udp are two different doors and get scanned separately. Flags (SYN, ACK, RST) exist only in TCP. In a SYN scan, SYN-ACK means open and RST-ACK means closed, and a RST on a closed port still proves the host is alive, which is how hosts get found when ping is blocked. In a UDP scan the only clear signal is the rejection, and it arrives from a different protocol: ICMP type 3 code 3. Silence is ambiguous (open or filtered), so the scanner waits for a timeout on every port, which is why UDP scans are slow and the logs of one look sparse.

**CSV exported from a SIEM, read with `cut`.** The trap: the timestamp has a comma inside (`Sep 7, 2025`), so every field in the data rows shifts by one relative to the header. In the lab, source IP was field 3, destination IP field 5, destination port field 6.

```
cut -d',' -f3 log.csv | sort | uniq -c                            who is scanning
cut -d',' -f5 log.csv | sort | uniq -c                            who is being scanned
grep '"192.168.230.1",' log.csv | cut -d',' -f6 | sort -n | uniq  ports probed on one host
```

The quotes and the trailing comma in the grep pattern are there so `.1` doesn't also match `.145` and `.127`.

**Zeek `conn_state`, the field that tells scan types apart in Kibana:**

```
S0      SYN seen, no reply ever          SYN scan against a filtered or dead host
REJ     SYN answered with RST            closed port
SF      full handshake and normal close  connect scan, or a real session
OTH     Zeek never saw the SYN           capture started mid-connection
```

`history` complements it: `S` is SYN only, `Sh` adds the SYN-ACK, an `A` after that is the ACK that completes the handshake. A connect scan completes it and then resets; a SYN scan never does. Whichever state dominates says which scan it was.

**Rogue assets.** Anything that answers on the network and isn't in the inventory: a personal laptop, a forgotten test server, a Wi-Fi router someone plugged in. No patches, no EDR, nobody watching. The defenders' own periodic scans exist partly to find these, and those scans have to be documented (source IP, type, schedule) so the detections exclude them instead of alerting on them.

## 3. Data exfiltration detection

**Exfiltration is the end of the chain, never the beginning**. So an exfil alert is never a single finding: by the time data leaves, the attacker is in, has moved and has collected, and all of that is sitting in the logs waiting to be found. What the channels in this room have in common is that they ride a protocol the firewall already allows, so detection is by behaviour (volume, length, destination, regularity), not by protocol.

**What to look for, per channel:**
| Channel | Where it shows in a log | What gives it away |
|---|---|---|
| DNS | query name, response code | Very long or random-looking names, hundreds of unique subdomains under one parent domain, many NXDOMAIN, TXT or NULL record types, regular intervals, several hosts doing the same |
| HTTP | method, bytes_sent, host | Large POSTs to an unknown or new domain; a host that sends far more than it receives |
| FTP | USER / PASS / STOR commands | Generic accounts (admin, backup, root, guest) uploading to an external IP, everything cleartext |
| ICMP | frame length, type | Echo requests well above the ~74 bytes of a normal ping, with no reply, from several hosts |


**DNS, the question I had.** Why is it exfiltration if the queries go to 8.8.8.8? Because the resolver is only the intermediary. It doesn't have the attacker's subdomain cached, so it resolves it recursively and the query ends up at the authoritative server for that domain, which the attacker controls. In the logs it looks like ordinary traffic to Google, and that is the point. The response barely matters: the data already travelled in the question. A high NXDOMAIN count is itself an indicator, because a normal host asks for names that exist.

**Wireshark filters that did the work:**

```
dns && frame.len > 70
dns && dns.qry.name contains "<suspicious domain>"
http.request.method == "POST" and frame.len > 750
ftp.request.command == "USER" || ftp.request.command == "PASS"
ftp contains "STOR"
icmp.type == 8 and frame.len > 100
```

**Splunk equivalents:**

```
index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count
index="data_exfil" sourcetype="dns_logs" | where len(query) > 30
index="data_exfil" sourcetype="http_logs" method=POST
  | stats count avg(bytes_sent) max(bytes_sent) by domain | sort -count
index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600
  | table _time src_ip uri domain dst_ip bytes_sent | sort -bytes_sent
```

The length threshold (30 in the lab) is a starting point, not a rule: CDNs and Microsoft services also use long subdomains. Length gets combined with randomness and with volume towards one parent domain.

**Two Wireshark lessons from the FTP part.** The `PASS` filter returned nothing, even though the credentials were right there: in that capture, `USER`, `PASS` and `STOR` travelled in the same packet, and Wireshark tags a packet by its first command only. The filter shows what the dissector interpreted; Follow TCP Stream (or the bytes pane) shows what actually went over the wire. When in doubt, follow the stream. And the account names were the tell: real users look like `jperez` or `e10452`; `admin`, `backup`, `root` and `guest` are the first entries in any wordlist, and all of them were connecting to the same external IP.

**GET vs POST, for context.** GET asks for something and carries little data in the URL; POST sends something and carries it in the body. Exfiltration over HTTP is almost always POST because of the volume, which is why the Initech IDS alert was "HTTP POST Large Upload". The behavioural clue is a host whose outbound bytes dwarf its inbound: normal browsing is the other way around.

## 4. MITM detection

**The chain in the lab, and the layer of each lie.** ARP (layer 2) lies about which MAC owns the gateway's IP. IP spoofing (layer 3) lies about who sent a packet, by writing a false source address. DNS (layer 7) lies about which IP a real domain name points to. SSL stripping isn't really a lie but an omission: the victim gets the real site served over plain HTTP, and the only thing missing is the padlock. Each step enables the next: without the ARP position the attacker doesn't see the DNS query; without the DNS answer the victim never connects to them; without that connection there is nothing to strip.

**IP spoofing vs DNS spoofing**, which took me a while to separate: one forges the envelope (the source IP in the header), the other forges the contents (the answer inside a DNS response). In the lab both were in the same packet, a fake DNS answer sent with 8.8.8.8 as its source so the victim would accept it.

**Last answer wins vs first answer wins.** ARP has no transaction ID: every `is-at` overwrites the previous entry, so the attacker has to keep repeating the false reply, and that repetition is the volume that gives it away. DNS matches responses to queries by ID and keeps the first one that arrives, so the attacker has to be faster than the real resolver. Being on the local network, they usually are. Two different mechanics, two different indicators.

**ARP.** Legitimate gratuitous ARP exists: a host that boots or changes IP announces its own address once. What is not legitimate is one IP announced by two different MACs, or one MAC announcing an IP that isn't its own, over and over. The filter that resolved the case was not the generic `arp` view, which was all noise, but pinning the gateway's IP and looking at who claims it:

```
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
arp.duplicate-address-detected || arp.duplicate-address-frame
```

**DNS.** Compare normal first, then look for what doesn't fit. The giveaway is a response for the target domain coming from an IP that is not the configured resolver, or two responses to the same query with different answers:

```
dns.flags.response == 1 && ip.src == 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
```

The first filter is the baseline, the second is the finding. A caveat I wrote down: the first filter trusts the source IP, and with IP spoofing that can be forged, so it has to be backed by the duplicate-response and inconsistent-answer checks (the same name resolving to different IPs, or unrelated names all resolving to the same one).

**SSL stripping.** The Client Hello of a TLS handshake is not encrypted and carries the SNI, the name of the site being requested. That is the one readable piece of an HTTPS connection, and it was what proved the portal normally used TLS:

```
tls.handshake.type == 1 && tls.handshake.extensions_server_name == "corp-login.acme-corp.local"
http && ip.src == 192.168.10.10 && ip.dst == 192.168.10.55
```

After the DNS redirect, the same portal shows up as plain HTTP between the victim and the attacker's IP, with the login POST readable. The defence on the server side is HSTS, which tells the browser to never try HTTP for that site again; modern browsers also attempt HTTPS first by default, which is why this attack is much weaker than it was in 2009.

**Kill chain placement.** MITM is Exploitation (abusing the trust built into ARP and DNS to get in the middle) and can become Installation if the position is used to tamper with an unencrypted download. Catching it means the attacker is mid-chain and hasn't reached the objective yet.

## 5. IDS fundamentals

**Firewall vs IDS.** The firewall reads the envelope (IPs, ports, protocol) and acts: allow or block, inline. The IDS reads the content and the behaviour and alerts; it sits to the side on a copy of the traffic. The DNS case above is the clean example: the firewall sees UDP to 8.8.8.8:53 and lets it through; the IDS sees an 80-character random query repeated 300 times and raises a flag. The IPS is an IDS placed inline that blocks, and most commercial firewalls today are NGFWs that include one.

**Two axes that are independent.** Where it sits (NIDS on the network, HIDS on the host) and how it detects (signatures for known patterns, anomalies against a baseline, or both). Any combination exists. A real SOC runs both detection modes at once: signatures catch most of what comes in, behaviour analysis in the SIEM looks for what has no signature yet.

**What defines NIDS vs HIDS is the data, not the host count.** A Snort instance on a single server is still a NIDS: it analyses that server's packets, but it has no idea which process generated them or which file was touched. For that you need an agent inside the system.

**The grid for the acronyms:**

```
            DETECTS ONLY                    DETECTS AND ACTS
Network     NIDS (= "IDS" when unqualified)  NIPS (= "IPS"), NBA for the behaviour-based kind
            Snort, Suricata, Zeek            Snort/Suricata inline, Palo Alto, Fortinet, Firepower
            off to the side, on a SPAN/TAP   inline at the perimeter, where blocking is worth the risk
Wi-Fi       —                                WIPS: rogue APs, deauth attacks; built into Meraki, Aruba
Host        HIDS: OSSEC, Wazuh, Tripwire     HIPS, which today means EDR: CrowdStrike, Defender,
            Linux servers, small setups      SentinelOne, Carbon Black. The corporate standard
```

Rules I wrote down to stop mixing them: IDS and IPS with no letter in front always mean network. HIDS alerts, HIPS/EDR acts; EDR is the commercial name HIPS acquired around 2013 when those products added remote investigation. NBA is just the anomaly-based flavour of NIPS, and it needs a training period to learn what normal looks like; a breach during that period poisons the baseline.

**Why not run everything as IPS if the software is free?** Because blocking has a cost that alerting doesn't: a badly tuned rule that produces a noisy alert in IDS mode takes down the billing system in IPS mode, the inline box becomes a single point of failure, and every packet waits for a verdict. The usual pattern is IPS at the perimeter and IDS inside, and many teams run IDS for months before promoting the rules they trust.

**SPAN vs TAP, and the sensor.** SPAN is a switch configuration that copies other ports' traffic to the sensor's port; a TAP is a physical device in the cable that sends a copy out. Either way the IDS gets a copy, which is why it can see everything and block nothing. The sensor is a Linux box running Snort or Suricata; nobody reads alerts on it. They go to the SIEM, where they appear as the `ids_logs` sourcetype did in the Initech case.

## 6. Snort

**Three modes, one tool.** Sniffer shows packets on the terminal (Wireshark without the GUI), logger saves them to a pcap, IDS/IPS compares them to rules. The modes are not rigid; they are names for combinations of flags, and I found it easier to read any Snort command by asking four questions:

```
where do packets come from?    -i <interface> live        -r <file> from a pcap
are rules applied?             -c <config>  yes, IDS mode  no -c: sniffer/logger only
what goes to the terminal?     -v headers  -d payload  -e MACs  -X hex   -A console/cmg for alerts
what goes to disk?             -l <dir> packets           -A fast/full alerts
                               -N turns packets off       -A none turns alerts off
```

Plus three that don't change what is analysed: `-T` validates the config and exits, `-q` suppresses the banner and the summary, `-D` runs in the background and gives the terminal back (then `ps -ef | grep snort` to find it and `kill -9 <pid>` to stop it).

**The two combinations I actually use:**

```
sudo snort -c local.rules -A console -r capture.pcap     test a rule against recorded traffic
sudo snort -c /etc/snort/snort.conf -A fast -D           production: alerts to file, running in the background
```

**Alert modes.** `console` and `cmg` print to the terminal (cmg adds the full packet); `fast` and `full` write to the alert file (full adds packet headers, but neither includes the payload); `none` writes no alerts at all. The payload is not lost: in IDS mode Snort also writes a pcap of the packets that fired, and that is where I go with `snort -r <log> -X` or Wireshark when I need to see what the packet carried.

**Logs belong to root.** Snort runs with sudo, so everything it writes needs sudo to read. `sudo cd` doesn't exist; either read from outside (`sudo cat dir/file`) or open a root shell with `sudo -i`. Logs saved with `-K ASCII` are readable with `cat` but cannot be reprocessed by Snort, tcpdump or Wireshark; if there is any chance of re-analysing, keep the binary pcap.

**Rule anatomy.** Header (action, protocol, source IP and port, direction, destination IP and port) and options in parentheses. Protocol is only `tcp`, `udp`, `icmp` or `ip`; application protocols are expressed as transport plus port plus content. Custom rules get a `sid` of 1,000,000 or higher and every option ends in a semicolon. `nocase` and `fast_pattern` modify the `content` right before them, and `fast_pattern` should mark the rarest string in the rule, not the first one, because it is the pre-filter that decides which packets get a full inspection.

**Debugging a rule that doesn't fire, in the order it happened to me.** First, I was editing `/etc/snort/rules/local.rules` while the exercise command loaded the `local.rules` in the task folder: edit the file the command actually reads. Second, my rule said `tcp` and the packet with that IP ID was ICMP: `ip` matches any protocol when you don't know. Third, with `-A full` nothing appears on screen; the alert is in the `alert` file. Fourth, the alert line never prints the field you filtered on, only IPs, protocol and message; to see the packet, open the `snort.log.*` it produced with `-X`. The packet turned out to be an ICMP timestamp request (type 13), which nobody uses for time sync anymore and Nmap uses to find hosts when echo requests are filtered.

**Reading the end-of-run summary.** `Breakdown by protocol` is Wireshark's Protocol Hierarchy in text form. `Action Stats: Alerts` is the count that answers "how many packets did the rule detect", as long as no rule uses thresholds. The preprocessor sections (HTTP methods counted, TCP segments queued) only exist when running with the full config, which is also why rules that depend on reassembly don't work when you run Snort with just `local.rules`.

## Key takeaways

- The three perimeter logs answer three different questions. Investigation is a chain of pivots between them, each finding being the search key for the next.
- Scanning, brute force and beaconing are visible as shapes before they are visible as content: one-to-many, one-to-one repeated, perfect intervals.
- An internal scan is a different incident from an external one. Blocking an IP fixes the second and does nothing for the first.
- Exfiltration hides in allowed protocols, so it is caught by behaviour: length, volume, direction, regularity, destination.
- In Wireshark, the filter shows what the dissector understood; the stream shows what went over the wire.
- IDS and IPS without a letter in front mean network. On the host it is HIDS, or EDR when it acts.
- Snort flags answer four questions: where packets come from, whether rules apply, what prints, what is saved. Test rules on a pcap with `-A console`; run production with `-A fast -D`.
