# Portfolio Case Study: Network Traffic Analysis, Email Forensics & Host Reconnaissance

**Author:** Annus Jawad  
**Role:** SOC Analyst / DFIR Trainee  
**Date:** October 14, 2026  
**Environment:** Kali Linux (x86_64)  
**Tools & Libraries:** Wireshark 4.6.4, Nmap 7.98, Python 3, `base64`, `md5sum`

---

## Executive Summary

This project demonstrates core Security Operations Center (SOC) and Digital Forensics and Incident Response (DFIR) methodologies across three key security domains:
1. **Network Telemetry Capture & Filtering:** Analyzing live wireless traffic to isolate protocols and inspect packet headers across OSI layers.
2. **Network Forensics & Artifact Recovery:** Reconstructing unencrypted application-layer sessions (SMTP) from raw packet captures (PCAP), recovering cleartext credentials, extracting embedded MIME attachments via Python, and verifying evidence integrity with cryptographic hashing.
3. **Host Discovery & Attack Surface Mapping:** Enumerating local and remote port states using active reconnaissance techniques to identify running services and assess exposure.

---

## Technical Skills & Tooling

| Category | Tools & Technologies | Focus Areas |
| :--- | :--- | :--- |
| **Packet Analysis** | Wireshark 4.6.4, PCAPNG | Display filters, protocol layer dissection, stream follow |
| **Digital Forensics** | Python 3 (`email` library), Base64, MD5 | Evidence extraction, hash verification, MIME parsing |
| **Reconnaissance** | Nmap 7.98, TCP/IP Suite | Service enumeration, port state analysis (`open`/`closed`/`filtered`) |
| **OS / Environment** | Kali Linux, Bash Shell | Command-line scripting, system administration |

---

## Project Structure & Findings

### Phase 1: Live Network Traffic Analysis & Telemetry Filtering

**Objective:** Capture live 802.11 network traffic, evaluate display filtering efficiency, and inspect packet encapsulation layer-by-layer.

#### Methodology & Results
- **Interface Monitored:** `wlan0` (Local IP: `192.168.1.205`, Gateway: `192.168.1.1`).
- **Capture Yield:** 278 total frames captured with zero dropped packets.
- **Protocol Distribution:**
  - **TCP Traffic:** 199 packets (71.6%) – predominantly encrypted TLS 1.2/1.3 sessions.
  - **DNS Lookups:** 34 packets (12.2%) – queries between client host and local gateway resolver.
  - **HTTP Traffic:** 4 packets (1.4%) – plain-text request/response exchanges.

#### Display Filter Analysis Matrix

| Filter Expression | Targeted Traffic | Matching Packets | % of Total Traffic |
| :--- | :--- | :--- | :--- |
| `tcp` | All TCP transport streams | 199 | 71.6% |
| `dns` | Domain name resolution queries/responses | 34 | 12.2% |
| `ip.addr == 192.168.1.205` | IPv4 packets associated with target host | 43 | 15.5% |
| `tcp.port == 80` | Plaintext Web traffic | 27 | 9.7% |
| `http` | Unencrypted HTTP application traffic | 4 | 1.4% |
| `http.request.method == "GET"` | HTTP GET requests specifically | 2 | 0.7% |

#### Deep Packet Dissection (Frame 22 Analysis)
* **Encapsulation Breakdown:**
  * **Layer 2 (Link):** Ethernet II frame (Length: 69 bytes / 552 bits).
  * **Layer 3 (Network):** IPv4 Header (`192.168.1.205` $\rightarrow$ `192.168.1.1`).
  * **Layer 4 (Transport):** UDP Datagram.
  * **Layer 7 (Application):** DNS Query.

---

### Phase 2: Email Forensics & Artifact Reconstruction

**Scenario:** Forensic investigation of a target packet capture file (`Puzzle.pcap`) involving intercepted communications.

#### Step 1: Session Recovery & Credential Extraction
Filtering for cleartext SMTP traffic revealed two unencrypted session streams. The target used `AUTH LOGIN` mechanisms without Transport Layer Security (TLS) wrapper protection.

* **Base64 Payload Decoding:**
  ```bash
  # Recovering Username Payload
  echo 'c25lYWt5ZzMza0Bhb2wuY29t' | base64 -d
  # Result: sneakyg33k@aol.com

  # Recovering Password Payload
  echo 'NTU4cjAwbHz=' | base64 -d
  # Result: 558r00lz
  ```

#### Step 2: Evidence Extraction via Python Automation
The session object was exported as an RFC 822 formatted file (`rendezvous.eml`). An automated Python script was developed using the standard `email` parsing library to safely extract base64-encoded MIME attachments without manual decoding errors.

```python
import email
from email import policy

# Parse RFC822 email file
with open("rendezvous.eml", "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

# Iterate through attachments and rebuild binaries
for part in msg.iter_attachments():
    filename = part.get_filename()
    if filename:
        with open(filename, "wb") as out_file:
            out_file.write(part.get_payload(decode=True))
        print(f"[+] Successfully extracted attachment: {filename}")
```

#### Step 3: Forensic Cryptographic Verification
To ensure data integrity and establish a chain of custody, MD5 hashes were calculated for extracted artifacts:
1. **Extracted File:** `secretrendezvous.docx`  
   * **MD5:** `9e423e11db88f01bbff81172839e1923`
2. **Extracted Media:** Unzipped target archive to extract embedded spatial marker image (`image1.png`).  
   * **MD5:** `aadeace50997b1ba24b09ac2ef1940b7`

#### Forensic Summary Table

| Investigation Vector | Recovered Artifact / Evidence |
| :--- | :--- |
| **Sender Email** | `sneakyg33k@aol.com` |
| **Sender Credentials** | `558r00lz` |
| **Recipient Email** | `mistersecretx@aol.com` |
| **Extracted Attachment** | `secretrendezvous.docx` |
| **Attachment Hash (MD5)** | `9e423e11db88f01bbff81172839e1923` |
| **Embedded Image Hash (MD5)** | `aadeace50997b1ba24b09ac2ef1940b7` |
| **Geographic Location Found** | Playa del Carmen, Mexico |

---

### Phase 3: Host Reconnaissance & Port Scanning

**Objective:** Conduct host exposure discovery across local and authorized remote endpoints to identify open attack surfaces.

#### 1. Localhost Attack Surface Assessment
- **Command:** `nmap -A -T4 127.0.0.1`
- **Results:**
  - All 1,000 scanned ports returned `closed` (TCP RESET).
  - Verification confirmed no unauthenticated daemons or rogue listening services were bound locally.

#### 2. Authorized Remote Target Enumeration
- **Command:** `nmap -F www.douglas.stebila.ca`
- **Results:** Fast profile scan identified 4 active open service ports on the target infrastructure.

| Port | Protocol | State | Service Name | Defensive Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **22** | TCP | `open` | SSH | Remote management daemon; requires SSH-key authentication and firewall IP restriction. |
| **80** | TCP | `open` | HTTP | Cleartext web interface; should redirect traffic to HTTPS (Port 443). |
| **443** | TCP | `open` | HTTPS | Secure encrypted web application service. |
| **8443** | TCP | `open` | HTTPS-Alt | Alternate secure service port/administrative management portal. |

---

## Defensive Engineering Takeaways

1. **Cleartext Vulnerabilities:** Base64 encoding is an encoding scheme, not encryption. Transmitting authentication headers over plaintext protocols (such as unencrypted SMTP or HTTP) leaves credentials susceptible to passive wiretapping. Mandatory TLS enforcement must be configured on all mail gateways and endpoints.
2. **Evidence Integrity:** When conducting digital evidence acquisition, computing cryptographic hashes (such as SHA-256 or MD5) immediately after extraction proves that the evidence remains untampered throughout the analysis cycle.
3. **Attack Surface Reduction:** Unused listening ports represent potential entry points for unauthorized access. Regular external port scanning enables SOC teams to enforce zero-trust network perimeter policies and audit host exposure profiles.