# pcap-portfolio
# Case-002 — "It's a Trap!" (2025-06-13)

**Summary:** Analysis of a Malware-Traffic-Analysis training PCAP demonstrating a Windows host (10.6.13.133) contacting TAG-124 / KongTuke infrastructure, receiving staged payload(s), and performing internal reconnaissance. This repo contains the technical report, IOCs, timeline, and commands to reproduce the network analysis.

## Quick findings
- Victim: 10.6.13.133
- Notable external IPs/domains: 83.137.149.15 (TLS payload ~33 MB), 104.21.16.1 (HTTP POSTs - windows-msgas.com), 104.16.230.132
- Suspicious SNI: hillcoweb.com, truglomedspa.com
- Likely behavior: TAG-124 / KongTuke TDS used to deliver payloads; post-download internal AD reconnaissance observed.

### Acknowledgements
  This analysis used training materials and a publicly-available PCAP from Malware-Traffic-Analysis.net. Special thanks to the maintainers and contributors of Malware-Traffic-Analysis.net for curating and providing high-quality, freely            accessible traffic captures and exercise writeups that enable learning and practical training for defenders. Please see https://www.malware-traffic-analysis.net for more exercises and attribution.
