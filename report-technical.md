# Technical CTI / SOC Report — Case-002 "It's a Trap!" (2025-06-13)

## Executive Summary
A Windows host (10.6.13.133) in an Active Directory environment initiated encrypted communications to external infrastructure (83.137.149.15) and downloaded a suspicious payload of ~33 MB. Subsequent connections to suspicious domains and internal AD traffic suggest compromise via a Traffic Distribution System (TDS), associated with the KongTuke campaign (TAG-124).  
The communication pattern indicates payload delivery and possible internal reconnaissance.

---

## Data Source
- PCAP: `2025-06-13-traffic-analysis-exercise.pcap`
- Host: 10.6.13.133 (Windows workstation)
- Tools: Wireshark 4.2.x, tshark 4.2.x, Zeek 5.x (Docker), awk, VirusTotal

---

## Methodology
1. **Initial survey**  
   - Wireshark Protocol Hierarchy → confirmed majority TCP (TLSv1.2 traffic dominant).  
   - Conversations → filtered on host 10.6.13.133.

2. **Suspicious conversations**  
   - Large TLS session: 10.6.13.133 → 83.137.149.15:443 (~33 MB server→client).  
   - HTTP POSTs to suspicious domains: `windows-msgas.com`, `hillcoweb.com`, `truglomedspa.com`.  

3. **Command-line validation**  
   ```bash
   # Bytes sent/received between victim and external server
   tshark -r case.pcap -Y "ip.addr==10.6.13.133 && ip.addr==83.137.149.15 && tcp" \
     -T fields -e ip.src -e frame.len | \
     awk '{bytes[$1]+=$2} END{for (i in bytes) print i,bytes[i]}'
   Result:
     83.137.149.15   33271471
     10.6.13.133       754451
→ Strong asymmetry indicates download/payload delivery.

4. **TLS inspection**
   . SNI values extracted → included suspicious domains.
   . Certificates matched known KongTuke/TDS infra.
5. **Zeek logs (summary)
   . conn.log: confirmed long-duration TLS sessions.
   . ssl.log: JA3 fingerprints captured (to be used in IOC list).
   . http.log: malicious HTTP POSTs with URIs (/windows.php).

Findings
  . Victim established outbound TLS sessions, not user-driven web browsing.
  . TLS session asymmetry shows inbound large payloads → malware delivery.
  . HTTP POST patterns consistent with beaconing/C2 callback.
  . Post-download, victim communicated with internal AD/DC services → likely reconnaissance or lateral movement.

MITRE ATT&CK Mapping
 . T1071.001 — Application Layer Protocol: Web Protocols (TLS/HTTPS)
 . T1105 — Ingress Tool Transfer
 . T1041 — Exfiltration Over C2 Channel (suspected, no evidence yet)
 . T1018 — Remote System Discovery (Kerberos/LDAP seen)

Detection Opportunities
  . Suricata rule: detect SNI values (hillcoweb.com, truglomedspa.com).
  . Zeek detection: JA3 fingerprint alerts.
  . SIEM correlation: Large asymmetric TLS flows (>20 MB server→client) from workstation to uncategorized IPs.

   
