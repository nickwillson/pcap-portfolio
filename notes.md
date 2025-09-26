### Analyst Notes — Case-002 "It's a Trap!" (2025-06-13)

## Environment
- Tools used: Wireshark, tshark, Zeek (Docker), foremost, awk, VirusTotal
- Lab: Isolated VM (Kali Purple), pcap workspace: `~/pcap-portfolio/case-002-its-a-trap/`
- Data source: Malware-Traffic-Analysis.net training PCAP `2025-06-13-traffic-analysis-exercise.pcap`

### Session Timeline (chronological notes)

### Step 0 — Preservation
- Copied original capture and made read-only:
  ```bash
          cp 2025-06-13-traffic-analysis-exercise.pcap case-002-original.pcap
          chmod 444 case-002-original.pcap
    ```

### Step 1 — Initial survey / top talkers
Command:
``` bash
tshark -r case-002-original.pcap -T fields -e ip.src -e ip.dst \
  | tr '\t' '\n' | sort | uniq -c | sort -nr | head -n 20 > ip_top.txt cat ip_top.txt
```

Observation: Internal host 10.6.13.133 is highly active — top talker. Marked as suspected victim.

### Step 2 — Bytes directionality (victim <> external)
Command (bytes per side):
```bash
tshark -r case-002-original.pcap -Y "ip.addr==10.6.13.133 && ip.addr==83.137.149.15 && tcp" \
  -T fields -e ip.src -e frame.len | awk '{bytes[$1]+=$2} END{for (i in bytes) print i, bytes[i]}'
```
Result recorded:
```
83.137.149.15   33271471
10.6.13.133       754451
```
Interpretation: Server → client >> client → server → indicates payload delivery/staging, not exfiltration.

### Step 3 — HTTP requests / POSTs
Command to list HTTP requests:
```bash
tshark -r case-002-original.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri | head -n 50
```
- Noted suspicious hosts & URIs seen in results:
    - Host 104.21.16.1 (SNI/Host: windows-msgas.com) — repeated POSTs
    - Host 104.16.230.132 (related)
    - Observed URIs / parameters like varying_rentals-calgary-predict-trycl, event-datamicrosoft.live

### Step 3 — HTTP requests / POSTs
Command to list HTTP requests:
```bash
tshark -r case-002-original.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri | head -n 50
```
- Noted suspicious hosts & URIs seen in results:
  - Host 104.21.16.1 (SNI/Host: windows-msgas.com) — repeated POSTs.
  - Host 104.16.230.132 (related).
  - Observed URIs / parameters like varying_rentals-calgary-predict-trycl, event-datamicrosoft.live.

### Step 4 — TLS / SNI / cert inspection
Extract SNI:
```bash
tshark -r case-002-original.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name | sort | uniq -c
```
- Noted SNI / domains:
  - hillcoweb[.]com (SNI observed)
  - truglomedspa[.]com (SNI observed)
- Note: TLS application-data frames from 83.137.149.15 were large — consistent with transfer of binaries or staged payloads.

### Step 5 — File extraction (attempt)
HTTP objects export:
```bash
tshark -r case-002-original.pcap --export-objects http,./http_objs || true
ls -lah http_objs || true
file http_objs/* 2>/dev/null || true
sha256sum http_objs/* 2>/dev/null > http_objs.hashes || true
```
Result: (list hashes in http_objs.hashes if files present). Do not execute artifacts.

### Step 6 — Zeek (docker) for logs & timeline
Command:
```bash
sudo docker run --rm -v "$PWD":/data zeek/zeek zeek -r /data/case-002-original.pcap
```
- Files inspected: conn.log, dns.log, ssl.log, http.log
- Zeek highlights: long-duration TLS sessions; resp_bytes >> orig_bytes for the victim↔83.137.149.15 connection.

### Key Observations & Conclusions (working)
- KongTuke / TAG-124 identified from surrounding indicators and VT/context — this is a Traffic Distribution System (TDS) used to deliver payloads. KongTuke is NOT the same as AZORult (AZORult is a separate info-stealer family sometimes distributed by TDSes). In short: KongTuke ≠ AZORult.Corrected victim IP: 10.6.13.133.
- Dominant behavior: payload delivery from 83.137.149.15 to the victim (approx. 33 MB inbound).
- Suspicious HTTP POST interactions with 104.21.16.1 (windows-msgas.com) and 104.16.230.132 — likely TDS landing/redirect activity.
- SNI values (hillcoweb.com, truglomedspa.com) observed in TLS handshakes — add to IOCs.
- KongTuke / TAG-124 identified from surrounding indicators and VT/context — this is a Traffic Distribution System (TDS) used to deliver payloads.
