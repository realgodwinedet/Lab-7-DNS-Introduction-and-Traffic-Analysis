# SBT-DF203-Lab7: Basic Networking Skills for Digital Forensics — Lab 7: DNS Introduction and Traffic Analysis

* **Report title:** SBT-DF203-Lab7
* **Student full name:** Godwin Edet Ikpi
* **Registration number:** 2025/FWSD/11267
* **Lab host used for dig/capture:** `kali` (`192.168.199.135`, interface: `eth0`)
* **Configured DNS resolver:** `192.168.199.2`
* **Authorised training PCAP used:** `dig_dns.pcap` (`frankwxu/digital-forensics-lab`, GitHub)
* **Assessment window:** 2026-09-19 00:00 WAT – 2026-09-22 23:59 WAT
* **Date of practical:** 2026-09-16

---

### 1. Objectives

This practical demonstrates the ability to:

* Explain foundational DNS resolution, including the roles of resolvers, authoritative servers, and record types.
* Query `A`, `AAAA`, `MX`, and `NS` records using `dig` and interpret status codes, flags, answers, TTL, and query time.
* Capture live DNS traffic and preserve it with a SHA-256 hash.
* Extract and tabulate DNS query and response fields, including transaction ID, question name, type, response code, answers, and TTL.
* Correlate a DNS response with a subsequent TCP connection using transaction ID and returned IP address.
* Recognise legitimate variation in DNS behaviour (e.g., multiple A records, CNAME chains, differing TTLs) versus anomalous behaviour.

---

### 2. Lab Environment

This practical was carried out in the ICDFA-approved isolated lab environment and/or using the authorised offline training PCAP supplied for SBT-DF203, as permitted by the manual. No production, third-party, or public network was targeted.

| Component | Detail |
| --- | --- |
| **Lab host (dig / capture)** | `kali`, Kali Linux, `192.168.199.135`, `eth0` |
| **Configured DNS resolver** | `192.168.199.2` (derived from `/etc/resolv.conf`) |
| **Capture tool** | Wireshark / tcpdump (version: tcpdump version 4.99.4, Wireshark 4.2.2) |
| **dig version** | DiG `9.18.24-1-Debian` |
| **Browser used for correlation activity** | Mozilla Firefox 123.0 |
| **Authorised training PCAP** | `dig_dns.pcap` — used only for the SBT-DF203 exercise as instructed |

---

### 3. DNS Resolution Fundamentals

The DNS resolution chain begins when an application requests a hostname resolution, prompting the client's stub resolver to check its local cache or query its configured recursive resolver (such as a local gateway or public resolver like `8.8.8.8`). If the recursive resolver does not have the record cached, it queries the root servers, which direct it to the appropriate Top-Level Domain (TLD) servers (e.g., `.com` or `.org`). The TLD servers then point to the domain's authoritative name servers, which hold the definitive resource records.

The final answer is returned down the chain to the client and cached according to the Resource Record's Time-To-Live (TTL) value, which dictates how long intermediate systems may cache the data before re-querying.

#### 3.1 Record types used in this lab

| Type | Purpose | Relevance to this lab |
| --- | --- | --- |
| **A** | Maps a hostname to an IPv4 address | Used to resolve the lab target host prior to HTTP/TCP correlation |
| **AAAA** | Maps a hostname to an IPv6 address | Queried to confirm whether IPv6 resolution is available/configured |
| **MX** | Identifies mail exchange servers for a domain | Queried for the optional SMTP-DNS correlation with Lab 4 evidence |
| **NS** | Identifies the authoritative name servers for a domain | Queried to confirm delegation and authority for the domain |

---

### 4. Step 1 — Identify the Configured DNS Resolver

The resolver configuration was identified before any traffic was generated, so that observed query destinations could be validated against the expected resolver.

```bash
$ cat /etc/resolv.conf
$ resolvectl status         # or: systemd-resolve --status
$ nmcli dev show | grep DNS

```

| Evidence item | Value |
| --- | --- |
| **Configured resolver IP(s)** | `192.168.199.2` |
| **Source of configuration** | DHCP-assigned |
| **Search domain (if any)** | Localdomain |

*Screenshot 1: resolver configuration output*

---

### 5. Step 2 — dig Queries: A, AAAA, MX, NS

Each record type was queried against the lab target domain and the response status, flags, answer section, TTL, and query time were recorded.

```bash
$ dig A example.com
$ dig AAAA example.com
$ dig MX example.com
$ dig NS example.com

```

| Query type | Status (opcode/rcode) | Answer(s) | TTL | Query time |
| --- | --- | --- | --- | --- |
| **A** | `NOERROR` | `172.66.147.243`, `104.20.23.154` | 5s | 91 msec |
| **AAAA** | `NOERROR` | `2606:4700:10::6814:179a`, `2606:4700:10::ac42:93f3` | 5s | 15 msec |
| **MX** | `NOERROR` | `0 .` (Null MX) | 5s | 2023 msec |
| **NS** | `NOERROR` | `elliott.ns.cloudflare.com.`, `hera.ns.cloudflare.com.` | 5s | 2023 msec |

*Screenshot 2: dig A output*

*Screenshot 3: dig AAAA output*

*Screenshot 4: dig MX output*

*Screenshot 5: dig NS output*

The `NOERROR` response code observed across the queries indicates that the DNS lookups completed successfully without any protocol errors. Standard flags noted in the header include `qr` (Query/Response flag set indicating a response packet), `rd` (Recursion Desired, requested by the client), and `ra` (Recursion Available, confirming the resolver supports recursive resolution).

In contrast, an `NXDOMAIN` (Non-Existent Domain) response code would signify that the queried domain name does not exist on the authoritative nameserver. The TTL (Time-To-Live) value returned as 5 seconds reflects the specific short caching policy configured by the domain's provider (Cloudflare) for edge load-balancing, whereas static records or other providers often employ longer TTLs to optimize caching efficiency versus rapid update flexibility.

---

### 6. Step 3 — Fresh DNS Capture and Hash

```bash
$ sudo tcpdump -i [IFACE] port 53 -w dns_capture.pcapng
  (in a separate session, trigger a fresh lookup, e.g.)
$ dig A [TARGET-DOMAIN]
$ sha256sum dns_capture.pcapng

```

| Evidence item | Value |
| --- | --- |
| **Capture file** | `dns_capture.pcapng` |
| **SHA-256 hash** | `9b358368a2903da74e0cd3d938f2505239e74a0b001c4687b1bb55c8024d0ebf` |
| **Capture timestamp** | Wed Sep 16 06:41:36 EDT 2026 |
| **Packets captured** | 2: 1 query, 1 response |

*Screenshot 6: Wireshark/tcpdump view of the fresh DNS capture*

---

### 7. Step 4 — Query/Response Field Extraction and Transaction-ID Correlation

The query and its matching response were located in the authorised `dig_dns.pcap` training file where specified and their fields were extracted and matched using the DNS transaction ID together with source/destination endpoint information.

#### 7.1 Query packet

| Field | Value |
| --- | --- |
| **Frame / packet number** | 1 |
| **Timestamp** | Sep 16, 2026 07:36:16.909897000 EDT |
| **Source IP : port** | `192.168.199.135 : 56495` |
| **Destination IP : port** | `192.168.199.2 : 53` |
| **Transaction ID** | `0x64e2` |
| **Query name (QNAME)** | `example.com` |
| **Query type (QTYPE)** | 1 (A) |
| **Flags** | `0x0120` (Standard query, Recursion Desired) |

#### 7.2 Response packet

| Field | Value |
| --- | --- |
| **Frame / packet number** | 2 |
| **Timestamp** | Sep 16, 2026 07:36:17.087328000 EDT |
| **Source IP : port** | `192.168.199.2 : 53` |
| **Destination IP : port** | `192.168.199.135 : 56495` |
| **Transaction ID** | `0x64e2` |
| **Response code (RCODE)** | `NOERROR` |
| **Answer(s)** | `172.66.147.243`, `104.20.23.154` |
| **TTL** | 5 |
| **Flags** | `0x8180` (Recursion Available) |

| Correlation check | Result |
| --- | --- |
| **Query transaction ID == response transaction ID** | Y (`0x64e2 == 0x64e2`) |
| **Response source IP:port == query destination IP:port (and vice versa)** | Y |
| **Response time delta (response timestamp − query timestamp)** | 177 ms |

*Screenshot 7: Wireshark detail pane showing the query and response frames side by side with matching transaction ID highlighted*

---

### 8. Step 5 — Browser DNS Inventory and Connection Correlation

Browser-generated DNS activity was captured while navigating to the lab target site, and at least one DNS answer was correlated with the subsequent TCP connection established to that resolved address.

```bash
$ sudo tcpdump -i [IFACE] port 53 or host [SERVER-IP] -w browser_dns_correlation.pcapng
  (in the browser, navigate to http(s)://[TARGET-DOMAIN])
$ sha256sum browser_dns_correlation.pcapng

```

| Item | Value |
| --- | --- |
| **Domain browsed** | `example.com` |
| **DNS answer (resolved IP)** | `104.20.23.154` (or `172.66.147.243`) |
| **TTL of answer** | `tshark -r browser_dns_correlation.pcapng -Y "dns.flags.response == 1" -T fields -e dns.time -e dns.a` |
| **Subsequent TCP SYN destination IP** | `104.20.23.154` |
| **Match to DNS answer? (Y/N)** | Y |
| **Time between DNS response and TCP SYN** | ~15–50 ms |

*Screenshot 8: capture showing the DNS response followed by the TCP three-way handshake to the same IP address*

No unusual variation observed. Standard DNS resolution for `example.com` successfully returned the destination IP address (`104.20.23.154`), immediately followed by a normal TCP three-way handshake and TLS negotiation to the resolved IP address.

---

### 9. Step 6 — Optional SMTP-DNS Correlation (Lab 4 Evidence)

| Item | Value |
| --- | --- |
| **Lab 4 evidence available? (Y/N)** | N |
| **MX record queried** | N/A |
| **SMTP server IP used in Lab 4 capture** | N/A |
| **Matches MX-resolved IP? (Y/N)** | N/A |

---

### 10. Forensic Interpretation and Discussion

Correlating DNS query and response transactions requires verifying both the transaction ID and the network endpoints (source and destination IP/ports). While the 16-bit transaction ID ensures that a returning response matches the specific query sent, relying on it alone is insufficient because transaction IDs can be spoofed or guessed by malicious actors in cache-poisoning or off-path injection attacks. Verifying that the response originates exclusively from the designated resolver (such as `8.8.8.8`) and maps back to the client socket ensures authenticity. Additionally, the Time-to-Live (TTL) value directly impacts future correlation work; a short TTL means a domain's resolved IP address can change rapidly, requiring analysts to capture traffic dynamically rather than assuming static record mapping. During a forensic review, indicators of suspicious DNS activity include mismatched transaction IDs, responses arriving from unauthorized sources or unexpected IP addresses, and records that conflict with an organization's known infrastructure or authoritative name servers.

---

### 11. Conclusion

This lab successfully demonstrated foundational network traffic analysis and forensic preservation techniques. Key accomplishments included identifying the local DNS resolver configuration, interpreting `A` and `AAAA` query results, and generating a hash-verified capture file to preserve evidence integrity. Furthermore, the analysis proved field-level correlation by matching query and response pairs through transaction IDs and successfully linking browser-generated DNS resolution outcomes directly to subsequent TCP connections and TLS handshakes.
