# Technical CTI / SOC Report — Case-002 *"It's a Trap!"* (2025-06-13)

## Executive Summary
A Windows workstation (`10.6.13.133`) in an Active Directory environment initiated encrypted communications with external infrastructure (`83.137.149.15`).  
Analysis shows ~33 MB of inbound payload over TLS, followed by HTTP POST requests to suspicious domains (`windows-msgas.com`, `hillcoweb.com`, `truglomedspa.com`).  

This traffic is linked to **KongTuke malware (TAG-124)**, delivered via a **Traffic Distribution System (TDS)**.  
Observed patterns indicate:
- **Payload delivery** via asymmetric TLS session.  
- **Beaconing/command-and-control** via HTTP POSTs.  
- **Potential reconnaissance** against internal AD/DC services.  

---

## Data Source
- **PCAP:** `2025-06-13-traffic-analysis-exercise.pcap`  
- **Victim Host:** `10.6.13.133` (Windows workstation, AD-joined)  
- **Tools Used:** Wireshark 4.2.x, tshark 4.2.x, Zeek 5.x (Docker), awk, VirusTotal  

---

## Methodology

### 1. Initial Survey
- **Wireshark Protocol Hierarchy:** confirmed TCP-heavy capture, with TLSv1.2 dominating.  
- **Conversations:** filtered on `10.6.13.133`.  
  - Identified suspicious external IP (`83.137.149.15`).  
  - Additional HTTP sessions to domains hosted on Cloudflare IPs.  

---

### 2. Suspicious Conversations
- **Large TLS session:**  
  - `10.6.13.133 → 83.137.149.15:443`  
  - ~33 MB inbound payload (server → client).  
- **HTTP POSTs:**  
  - Domains: `windows-msgas.com`, `hillcoweb.com`, `truglomedspa.com`.  
  - Pattern: repeated POST requests, typical of beaconing/C2 callbacks.  

---

### 3. Command-Line Validation

```bash
# Bytes sent/received between victim and external server
tshark -r case.pcap -Y "ip.addr==10.6.13.133 && ip.addr==83.137.149.15 && tcp" \

Result:
   83.137.149.15   33271471
   10.6.13.133       754451
```
Interpretation:
Strong asymmetry → victim downloaded payload from external server.

### 4. TLS Inspection
- SNI values: included suspicious domains above.
- Certificates: overlapped with known KongTuke/TDS infrastructure.
- Zeek ssl.log: JA3 fingerprints extracted for future detection.

### 5. Zeek Logs (Highlights)
- conn.log: long-duration TLS sessions.
- ssl.log: JA3 values suggest commodity malware.
- http.log: POSTs to /windows.php endpoints.

Findings
1. Victim established outbound TLS sessions not tied to user-driven browsing.
2. Large asymmetric TLS flows show malware payload delivery.
3. Beaconing behavior via repeated HTTP POSTs.
4. Victim later talked to internal AD/DC services → potential reconnaissance/lateral movement.

### MITRE ATT&CK Mapping
- T1071.001 — Application Layer Protocol: Web (TLS/HTTPS)
- T1105 — Ingress Tool Transfer (payload delivery)
- T1041 — Exfiltration Over C2 Channel (suspected)
- T1018 — Remote System Discovery (internal DC communication)

### Detection Opportunities
- Suricata/YARA: SNI matches (hillcoweb.com, truglomedspa.com).
- Zeek: JA3 fingerprint alerts for TLS sessions.
- SIEM Correlation: Flag large (>20 MB) asymmetric TLS sessions from workstations.

### Conclusion
Traffic demonstrates a KongTuke (TAG-124) intrusion attempt via malicious TDS redirectors.
The compromise shows:
- Initial infection vector via suspicious HTTP traffic.
- Payload delivery (~33 MB) over encrypted TLS.
- Possible C2 beaconing and reconnaissance activity in AD environment.

### SOC Priority: HIGH.
   Immediate hunting for IOCs and host-level triage recommended.
   
### Acknowledgements
   This analysis used training materials and a publicly-available PCAP from **Malware-Traffic-Analysis.net**. Special thanks to the maintainers and contributors of Malware-Traffic-Analysis.net for curating and providing high-quality, freely     accessible traffic captures and exercise         writeups that enable learning and practical training for defenders. Please see https://www.malware-traffic-analysis.net for more exercises and attribution.
      
