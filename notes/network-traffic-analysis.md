# Network Traffic Analysis — Study Notes

TryHackMe SOC Level 1 · Network Traffic Analysis module (5 rooms) · Completed September 2026

Working notes from the module. I kept the parts I expect to use again when a network alert comes in.

## 1. Why network traffic analysis

The example that made it click for me: host WIN-016 (192.168.1.16) sends DNS queries like `aj39skdm.malicious-tld.com` (type A) and then `cmd01.malicious-tld.com` (type TXT). An A record can only carry an IP address, so there is no room to hide anything in the answer. A TXT record carries free text, and the domain owner decides what goes in it. Random subdomains going out plus TXT answers coming back means data leaving and commands arriving, inside a protocol that firewalls almost always allow.

Some things only exist in the packet and never reach a log: TCP sequence numbers, window size, MAC addresses. The log is a summary. The capture is the evidence.

How the tools fit together (this confused me at first):

```
Suricata (IDS)   alerts        always on, only speaks when a rule matches
Zeek             logs          always on, records everything without judging
SIEM             correlation   always on, one place to query every source
Wireshark        packets       on demand, when I open the pcap
```

The alert says something happened. The SIEM, with the Zeek logs inside, gives me the context: who else the host talked to, if the connection pattern is regular (beaconing), if there are signs of lateral movement to other internal machines. Wireshark is for when I need the content itself: the command inside a DNS answer, a file I can export and hash, or a field like window size that no log records.

Two other ideas from the module: intermediary devices (firewalls, switches, proxies) versus endpoints as traffic sources, and north-south traffic (crosses the perimeter, watched closely) versus east-west (stays inside the LAN, watched less, and where lateral movement happens).

## 2. Wireshark basics

Three panes: packet list, packet details, packet bytes (hex on the left, text on the right). The details pane breaks each frame down by layer: Frame, Ethernet, IP, TCP or UDP, then the application protocol. Any field in that tree can become a filter or a column with a right click. Adding a column is usually what makes an anomaly visible without opening packets one by one.

Coloring rules and Expert Info are hints, not verdicts. Expert Info flags sequence jumps all the time and it is almost never an attack.

## 3. Packet operations

Capture filters decide what gets recorded. Display filters decide what I see. In the module I only used display filters.

The ones I used most:

```
ip.addr == 10.10.10.111        source OR destination
ip.src == 10.10.10.111         source only (matters when following one flow)
tcp.port == 80  /  udp.port == 53
http.request.method == "POST"  data sent to the server: login forms, uploads, Log4j attempts
dns.flags.response == 0        queries only (the client asking)
dns.qry.type == 1              A records (TXT is 16)
tcp.flags.syn == 1 and tcp.flags.ack == 0
frame contains "jndi"
```

`contains` is a substring match, `matches` takes a regex, `in` checks a set of values. Nobody memorizes the fields of 3000 protocols; the Display Filter Expression builder lists every field with its valid values, so I don't need to remember that TCP is protocol 6.

Statistics menu: Protocol Hierarchy to see what the capture is made of, Conversations and Endpoints to see who talked to whom. Follow TCP Stream to read a session as text. File → Export Objects to pull files out of HTTP, SMB or FTP and hash them.

## 4. Traffic analysis: what each attack looks like

**Nmap scans.** The three types side by side:

```
                 open port              closed port         window
TCP connect      SYN / SYN-ACK / ACK    SYN / RST-ACK       > 1024
(-sT, no root)   then RST-ACK
SYN scan         SYN / SYN-ACK / RST    SYN / RST-ACK       <= 1024
(-sS, root)
UDP              no reply               ICMP type 3 code 3    -
```

A question I had while doing it: why does the attacker's source port keep changing? In a TCP connect scan, Nmap asks the OS for a normal connection to each port, and the OS gives a new ephemeral port to every connection. A SYN scan builds its own packets, so Nmap picks the source port itself and usually keeps the same one for the whole burst (36044 in the lab). Changing source ports point to a connect scan; a fixed one points to a SYN scan. The most useful single filter is `tcp.flags.syn == 1 and tcp.flags.ack == 1`: it lists the SYN-ACKs, which is the list of ports the scanner found open.

**ARP poisoning.** Normal ARP is two packets: a broadcast asking who has an IP, and one answer. The red flag is two different MACs answering for the same IP. Wireshark marks the duplicate in Expert Info, but only the second one; deciding which is the real one is my job. In the lab, a MAC ending in b4 owned 192.168.1.25, sent ARP requests to a whole range, and then claimed the gateway's IP. To confirm the MITM I had to look at HTTP traffic in the same time window and find that MAC on packets where it should not be. The attack only became visible by connecting small findings, so I kept a list as I went.

**Identifying hosts.** DHCP Requests carry the hostname (option 12) and the client MAC (61). ACKs carry the domain name (15) and the lease time. NAKs carry a reason message (56) that is better read than filtered. NBNS queries show NetBIOS names, and Kerberos tickets show usernames in `CNameString`. With the three of them you can usually link an IP to a hostname and a user.

**Tunneling.** ICMP: `data.len > 64 and icmp`. A normal echo is 64 bytes and a tunnel needs room for payload. Attackers can pad packets to look normal, so volume and destinations matter too. DNS: long, encoded-looking subdomains all pointing at one domain, high query counts, TXT answers. In both cases the tunnel appears after something already ran on the host. It is the communication channel, not the way in.

**Cleartext protocols, FTP.** Username and password travel in the `USER` and `PASS` commands. The response codes show what happened without opening packets: 230 logged in, 530 bad password, 227 passive mode (a transfer is coming). Many 530 in a row is brute force. A 230 after many 530 means the attacker got in.

**Cleartext protocols, HTTP.** Three places to look: POST bodies (login forms), Basic auth headers (Base64 is encoding, not encryption), and the User-Agent. I add User-Agent as a column and look for tool names (`sqlmap`, `Nmap`, `Nikto`, `Wfuzz`), misspellings (`Mozlilla`), and the same host changing agents in a short time. Never whitelist a user agent because it looks normal; it is the easiest field to fake. For Log4j: POST requests, `jndi:ldap`, `Exploit.class`, and `$` or `==` inside the user agent (the start of the exploit string, and Base64 padding).

**Decrypting HTTPS.** With the client's TLS key log file loaded in Wireshark's TLS preferences, the sessions get decrypted and the HTTP inside becomes readable and exportable. Without the keys there is nothing to do at packet level.

**Two tools I did not know existed.** Tools → Credentials lists every cleartext credential the FTP, HTTP, IMAP, POP and SMTP dissectors found, with clickable packet numbers. Seeing them as a list is what shows the pattern: the same username repeated many times in a few packets is brute force, not a user who mistyped. Tools → Firewall ACL Rules generates blocking rules (iptables, Cisco IOS, pf, Windows netsh) from a selected packet. Careful: they are written for the external interface of a firewall.

## 5. NetworkMiner

Passive network forensics tool. It parses a pcap and gives an overview without sending a single packet. The free edition was enough for the room.

Where to look depending on the question:

```
who is on the network                       Hosts
what talked to what                         Sessions
which domains were looked up                DNS
users, passwords and password hashes        Credentials
files transferred                           Files
HTTP headers and form fields                Parameters (User-Agent, Referer, cookies)
search for a specific string                Keywords (add it, then reload the case files,
                                              or the list stays empty)
what it can flag on its own                 Anomalies (ARP spoofing, EternalBlue / MS17-010)
```

It has a sniffer mode, but only on Windows, and the module itself says not to rely on it. My workflow: capture, then NetworkMiner for the overview, then Wireshark for the details. Version matters: 2.7 correlates MACs and parses more parameters, 1.6 keeps the per-packet Frames tab and the Cleartext tab. If something is missing in one, I check the other before going back to Wireshark.

## Key takeaways

- The log tells me what happened. The packet is the evidence, and some fields never reach a log.
- TCP sequence jumps are almost never an attack (retransmissions, loss, reordering). Hijacking is good to understand, not something to chase as an alert.
- Columns and Statistics before reading packet by packet. Most anomalies were visible at a glance once the right column was there.
- The scanner's list of open ports is one filter away: the SYN-ACKs.
- ARP spoofing is a correlation exercise: duplicate MAC, ARP flood, then the reflection in HTTP.
- NetworkMiner first for the overview, Wireshark after for the details.