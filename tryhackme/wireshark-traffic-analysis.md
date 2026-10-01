

Wireshark traffic analysis · MD
Wireshark: Traffic Analysis — ARP Poisoning and Man-in-the-Middle
Room: Wireshark: Traffic Analysis Path: SOC Level 1 → Network Traffic Analysis Date completed: August 2026

Scenario
The room provides a packet capture from a small network with one gateway and a few hosts. The task was to find out whether the ARP traffic in the capture is normal, and if not, identify who is behind it and what they achieved. This writeup covers that investigation. The same room also includes Nmap scan detection, DNS/ICMP tunneling and cleartext credential hunting; those are summarized in my study notes.

Why ARP is a good target
ARP maps IP addresses to MAC addresses inside a local network. It has no authentication: any host can answer "I have that IP" and the others will believe it. Each device keeps its own ARP table, entries expire, and that is why an attacker repeats the false answers in a loop. If the attacker convinces a victim that the gateway's IP belongs to the attacker's MAC, the victim's traffic goes through the attacker first. ARP poisoning is the technique; the man-in-the-middle position is the result.

Because the mechanics are always the same, detection comes from knowing what normal ARP looks like: a broadcast request asking who has an IP, and one reply from the host that has it.

Show Image

Step 1: Finding the conflict
Wireshark flags IP-to-MAC conflicts in Expert Info. Filtering for them:

arp.duplicate-address-detected or arp.duplicate-address-frame
Two different MACs were answering for the same IP, 192.168.1.1, which by its number looked like the gateway:

MAC	Claimed IP
50:78:b3:f3:cd:f4	192.168.1.1
00:0c:29:e2:18:b4	192.168.1.1
Wireshark only marks the second occurrence of the duplicate, so it does not say which one is legitimate. That part is on the analyst. One more detail from the same filter: the MAC ending in b4 had earlier announced itself as 192.168.1.25, and was now claiming a different IP than the one it already had. The fake reply was not a broadcast either: it went straight to the victim's MAC (00:0c:29:98:c7:a8), so the attacker only lied to the host it wanted to intercept.

Show Image

Step 2: The ARP flood
Following the b4 MAC showed a second anomaly: 49 of the 50 packets in this capture were ARP requests from that same MAC, one every ~10 ms, asking for addresses across the whole 192.168.1.x range in random order.

((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == 00:0c:29:e2:18:b4)
A flood like this can be malicious activity, a scan, or a network problem, so on its own it is not a verdict. Combined with the conflict from step 1, the picture starts to form: the host at 192.168.1.25 swept the network with ARP requests and then claimed the gateway's address.

Show Image

Step 3: Confirming the MITM in HTTP traffic
The next step was to look for the effect of the poisoning in other protocols in the same time window. At the IP level the HTTP traffic looked normal: nothing connected it to the ARP findings. The key was adding the source and destination MAC addresses as columns in the packet list (eth.src, eth.dst), to see who was really behind each IP.

Every HTTP packet had the b4 MAC as its destination, in both directions: the victim's requests to 44.228.249.3 and the server's responses back to 192.168.1.12. That means both the victim and the gateway had been poisoned, and the attacker was seeing the whole conversation. The first request was a GET /login.php, so whatever the victim typed on that page went through the attacker in cleartext.

Show Image

Findings
Role	IP	MAC
Attacker	192.168.1.25	00:0c:29:e2:18:b4
Gateway	192.168.1.1	50:78:b3:f3:cd:f4
Victim	192.168.1.12	00:0c:29:98:c7:a8
BEFORE (normal)
  Victim .12  <------------------->  Gateway .1  <---> Internet

AFTER (ARP poisoning)
  Victim .12  ----> Attacker .25 (MAC ...b4) ----> Gateway .1 ---> Internet
                         |
                    reads everything
                    that passes through
The attacker generated all the ARP noise in the capture, poisoned both the victim and the gateway, and was receiving the HTTP traffic in both directions. Since HTTP is cleartext and the victim was on a login page, any credentials sent were readable by the attacker.

MITRE ATT&CK Mapping
Technique	ID	Notes
Adversary-in-the-Middle: ARP Cache Poisoning	T1557.002	False ARP replies claiming the gateway's IP
Network Sniffing	T1040	Victim's HTTP traffic redirected through the attacker
Remote System Discovery	T1018	ARP sweep of the local range before the attack
IOCs
Lab environment with private addresses, so there is nothing to defang here. In a real case the attacker's MAC and IP would go to the network team to locate the physical port or the VM.

Type	Value
Attacker MAC	00:0c:29:e2:18:b4
Attacker IP	192.168.1.25
Spoofed IP	192.168.1.1 (gateway)
Victim IP	192.168.1.12
What I would do next in a real SOC
Isolate the port or VM behind 00:0c:29:e2:18:b4 (the 00:0c:29 prefix is VMware, which fits a lab, but in production it would be a clue too).
Check the victim for credentials sent over HTTP during the window and force a reset.
Look for the same MAC in DHCP and switch logs to find when it joined the network.
Ask why HTTP without TLS was in use at all.
Conclusion
None of the three findings proved the attack alone. The duplicate address was a conflict, the flood could have been a scan, and the HTTP traffic looked normal at the IP level. The case came together by correlating them and by adding MAC columns to see the layer where the attack actually happens. In a real capture the data is not prepared for the investigation like in the exercise, so knowing the normal ARP flow and keeping a list of findings as I go is what makes this repeatable.


