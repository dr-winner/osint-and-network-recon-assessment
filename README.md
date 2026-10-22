# PENETRATION TESTING REPORT
## FOOTPRINTING & NETWORK SCANNING PHASES
### `SECURITY ASSESSMENT & RECONNAISSANCE`

---

| Field | Details |
| :--- | :--- |
| **Lead Assessor** | dr-winner |
| **Assessment Type** | OSINT, External Footprinting & Subnet Enumeration |
| **Date** | August 2026 |
| **Assessment Modules** | • **Module 1**: Multi-Vector Footprinting (Kali Linux Recon Suite)<br>• **Module 2**: Search Engine Intelligence & Google Dorking (GHDB)<br>• **Module 3**: Visual OSINT Link Analysis (Maltego Graph)<br>• **Module 4**: Passive Asset Discovery & Intelligence (theHarvester)<br>• **Module 5**: Active Subnet Discovery & Service Enumeration (Nmap / Zenmap) |
| **Scope & Target Assets** | 1. **Primary Domain**: `networkwalks.com` (Authorized external scope)<br>2. **Internal Segment**: Local LAN Subnet (`192.168.64.0/24`) |
| **Engagement Authorization** | Written client authorization & defined Rules of Engagement (RoE) |
| **Phases Covered** | • Phase 1: Passive Reconnaissance & Intelligence Gathering<br>• Phase 2: Active Network Discovery & Port Enumeration |

---

## 1. Liability Disclaimer

All security assessment and scanning activities documented in this report were performed strictly within defined, authorized boundaries and upon infrastructure where explicit written permission was secured, or on privately controlled lab environments. These materials are provided for professional security auditing and educational reference. Testing against systems without prior mutual written consent violates computer security laws across multiple jurisdictions.

---

## 2. Executive Assessment Overview

This assessment encompasses external footprinting against the `networkwalks.com` perimeter using Kali Linux reconnaissance tooling (Module 1), search engine intelligence and Google Hacking Database methodologies (Module 2), visual link and entity analysis with Maltego (Module 3), non-intrusive passive subdomain harvesting via theHarvester (Module 4), and local network host discovery and port profiling via Zenmap/Nmap (Module 5).

Together, these exercises demonstrate the end-to-end reconnaissance lifecycle: how threat actors transition from passive, zero-noise open-source intelligence gathering to active, targeted host discovery.

All procedures were executed in controlled environments across Kali Linux and dedicated scanning workstations. Each activity details the tool invoked, technical observations, sanitized evidence, and the operational risk posed to enterprise infrastructure. *(Note: Hardware MAC addresses, internal directory paths, and third-party live endpoints have been masked in accordance with responsible security disclosure standards).*

---

## 3. Tooling & Technical Methodology

The table below outlines each tool leveraged during this assessment and its operational role:

| Tool | Assessment Role |
| :--- | :--- |
| **Kali Linux & Windows** | Primary operating systems and execution environments for OSINT and active scanning. |
| **WHOIS** | Domain registrar profiling, registration lifecycles, and nameserver delegation enumeration. |
| **WhatWeb** | Web application fingerprinting (CMS detection, web server banners, frameworks, and IP). |
| **Nslookup** | DNS name resolution and host IP mapping. |
| **cURL (`curl -I`)** | HTTP/2 response header inspection, server signature analysis, and cache evaluation. |
| **Wafw00f** | Web Application Firewall (WAF) perimeter detection and fingerprinting. |
| **DNSRecon** | Comprehensive DNS zone enumeration (SOA, NS, MX, SPF, TXT, SRV) and daemon version discovery. |
| **Google Hacking (GHDB)** | Advanced search query engineering to uncover exposed management consoles and index leaks. |
| **Maltego Graph (Desktop)** | Transform-based visual link analysis, domain infrastructure mapping, and corporate entity relationships. |
| **theHarvester** | Passive public intelligence gathering for subdomains and email addresses without direct target interaction. |
| **Zenmap (Nmap GUI)** | Active subnet host discovery, TCP port enumeration, and service fingerprinting. |
| **Windows CMD (`ipconfig`)** | Network interface configuration, gateway identification, and local addressing verification. |

---

## 4. Assessment Activities & Execution

### 4.1 Multi-Vector Footprinting & Reconnaissance (Module 1)

External reconnaissance was conducted against `networkwalks.com` using six targeted analysis tools: **WHOIS**, **WhatWeb**, **Nslookup**, **cURL**, **Wafw00f**, and **DNSRecon**.

- **WHOIS**: Queried domain registration infrastructure, identifying GoDaddy as the registrar, active registration term (2019–2027), HostGator authoritative nameservers (`ns6135.hostgator.com`, `ns6136.hostgator.com`), and active WHOIS privacy masking.
- **WhatWeb**: Identified WordPress 7.0.4, WP Download Manager 3.3.58, Apache web server, jQuery 3.7.1, Bootstrap 7.0.4, and hosting IP address `192.232.216.135`.
- **Nslookup**: Resolved `networkwalks.com` directly to host IP `192.232.216.135`.
- **cURL (`curl -I`)**: Retrieved HTTP/2 200 response headers, exposing Apache web server signatures, caching mechanisms (`x-nginx-cache: WordPress`), and the exposed WordPress REST API endpoint `/wp-json/`.
- **DNSRecon**: Enumerated DNS records including NS, SOA, MX (`mail.networkwalks.com`), SPF policies, cPanel autodiscover SRV records, and exposed BIND version `9.16.23-RH`.
- **Wafw00f**: Verified the web perimeter is actively monitored and protected by a **ModSecurity (SpiderLabs) WAF**.

---

### 4.2 Search Engine Intelligence & GHDB (Module 2)

Utilized advanced Google search operators (`intitle:`, `inurl:`, `site:`, `filetype:`) to identify exposed, misconfigured surveillance feeds and publicly accessible infrastructure endpoints *(endpoints partially sanitized)*:

#### 10x Exposed Surveillance Devices & Streaming Endpoints (Sanitized)
| No. | Target Link (Sanitized) | Relevant Dork | Access Status |
| :-: | :--- | :--- | :--- |
| 1 | `http://122.116.41.xxx:8080/` | `intitle:"webcamXP" inurl:8080` | Open webcamXP live stream |
| 2 | `https://www.lmc.edu/webcam.htm` | `intitle:"Webcam" inurl:WebCam.htm` | Public campus webcam |
| 3 | `http://198.41.49.xxx:81/main.htm` | `intitle:"Device(IP CAMERA)" "language" -com\|net` | Direct IP camera stream |
| 4 | `http://86.122.80.xxx/Pages/login.htm` | `intitle:"NoVus IP camera" -com` | NoVus camera login interface |
| 5 | `https://www.skylinewebcams.com/en/webcam/...` | `inurl:webcam site:skylinewebcams.com inurl:roma` | Public live broadcast feed |
| 6 | `https://www.skylinewebcams.com/en/webcam/...` | `inurl:webcam site:skylinewebcams.com inurl:roma` | Public live broadcast feed |
| 7 | `http://109.233.191.xxx:8080/multi.html` | `intitle:"webcamXP" inurl:8080` | Multi-channel webcamXP stream |
| 8 | `http://72.199.200.xxx:8080/` | `intitle:"Index of" "DCIM/camera"` | Open directory with camera files |
| 9 | `http://139.64.168.xxx:8080/` | `intitle:"Index of" "DCIM/camera"` | Open directory camera media storage |
| 10 | `http://75.149.26.xxx:1024/` | `intitle:"webcamXP" inurl:8080` | webcamXP stream on port 1024 |

---

### 4.3 Visual OSINT Link Analysis with Maltego (Module 3)

Using Maltego Graph 4.12.1, performed entity extraction and visual link analysis:
- Configured Maltego Data Hub transforms and API connections.
- Executed email transforms against `networkwalks.com` to map public contact associations (`info@networkwalks.com`).
- *Demonstration Scenario*: To evaluate transform capability on large corporate datasets, executed entity transforms against `microsoft.com` to illustrate graph clustering, MX distribution, and corporate contact mapping.

---

### 4.4 Passive Reconnaissance with theHarvester (Module 4)

Using `theHarvester 4.11.1`, performed non-intrusive asset discovery:
- Executed `theHarvester -d microsoft.com -l 1000 -b baidu` as a passive reconnaissance showcase, discovering 8 public subdomains (`learn.microsoft.com`, `account.microsoft.com`, `support.microsoft.com`, etc.) without touching target infrastructure.
- Tested multi-source queries (`-b all`) and cataloged threat intelligence API integration options.

---

### 4.5 Active Subnet Scanning with Zenmap / Nmap (Module 5)

Conducted internal host discovery and service port enumeration on local subnet `192.168.64.0/24`:
- Identified local interface `192.168.64.10`, subnet mask `255.255.255.0`, and default gateway `192.168.64.1` via `ipconfig /all`.
- Executed fast TCP scan: `nmap -T4 -F 192.168.64.0/24`.
- Enumerated 3 live systems within the segment:
  - **`192.168.64.1`** (Gateway Router): Ports `53/tcp` (DNS) and `5000/tcp` (UPnP) open *(MAC address sanitized)*.
  - **`192.168.64.2`** (Internal Web Server): Port `80/tcp` (HTTP) open *(MAC address sanitized)*.
  - **`192.168.64.10`** (Windows Workstation): Ports `135/tcp` (MSRPC), `139/tcp` (NetBIOS), and `445/tcp` (SMB) open.

---

## 5. Risk Analysis / Impact

Based on the information gathered during external footprinting and internal network scanning, the following risks were identified:

| # | Risk / Finding | Evidence / Observation | Potential Impact | Risk Level |
| :-: | :--- | :--- | :--- | :-: |
| 1 | **Web Technology Banner Disclosure** | WhatWeb identified WordPress 7.0.4 and WP Download Manager 3.3.58 | Detailed version disclosure accelerates targeted exploit identification. | 🟡 **Medium** |
| 2 | **DNS Daemon Version Disclosure** | DNSRecon exposed BIND version `9.16.23-RH` and zone records | Detailed daemon metadata assists adversaries in fingerprinting OS/distro vulnerabilities. | 🟡 **Medium** |
| 3 | **Internal Host & SMB/NetBIOS Exposure** | Zenmap identified 3 live hosts and active SMB (445) / NetBIOS (139) on `192.168.64.10` | Unrestricted internal SMB services facilitate lateral movement and NTLM relay attacks. | 🟡 **Medium** |
| 4 | **Origin Server IP Exposure** | Nslookup resolved domain directly to `192.232.216.135` | Direct origin IP disclosure enables attackers to bypass edge protection and WAF filtering. | 🟢 **Low** |
| 5 | **HTTP Server & REST API Headers** | cURL returned verbose headers and exposed `/wp-json/` | Exposes internal CMS structure and available API endpoints. | 🟢 **Low** |
| 6 | **WAF Architecture Fingerprinted** | Wafw00f identified ModSecurity (SpiderLabs) | Informs attackers of inspection mechanisms, enabling tailored WAF evasion techniques. | 🟢 **Low** |

**Risk Level Key**: 🔴 Critical | 🟡 Medium | 🟢 Low

*Assessment Context*: The findings above reflect informational and architectural disclosures discovered during passive and active reconnaissance. These disclosures do not constitute confirmed exploitations but represent the foundational intelligence an attacker leverages to prioritize subsequent attack phases.

---

## 6. Defensive Recommendations

1. **Suppress Public Technology Banners**: Minimize verbose application banners in HTTP response headers and disable default server tokens (`ServerTokens Prod`, `ServerSignature Off`).
2. **Harden DNS Configurations**: Suppress BIND version responses (`version.bind` CHAOS TXT queries) and restrict zone transfers (`axfr`).
3. **Enforce WAF Security Controls**: Continuously tune ModSecurity rule sets (OWASP Core Rule Set) to block automated scanner probes and technology fingerprinting.
4. **Isolate Internal Management & SMB Services**: Enforce host-based firewalls on workstations to restrict inbound ports 135, 139, and 445 to approved administration subnets only.
5. **Disable UPnP on Edge Gateways**: Disable Universal Plug and Play (UPnP) on router/gateway devices to prevent unauthorized automated port forwarding.
6. **Implement Continuous Attack Surface Monitoring**: Routinely execute passive external asset discovery to catch orphaned subdomains, unintended cloud resources, or exposed files before external actors do.

---

## 7. Executive Summary & Conclusion

This assessment successfully validated the critical role of structured intelligence gathering in modern security assessments. Across five structured phases—ranging from non-intrusive DNS and WHOIS footprinting to passive search-engine intelligence, visual graph correlation, and active subnet discovery—the engagement demonstrated how seemingly isolated metadata points can be synthesized into an actionable attack map.

Key takeaways from the engagement include:
1. **Perimeter Hardening:** While perimeter defenses such as ModSecurity WAF are actively in place, underlying software versions (WordPress, WP Download Manager, Apache, BIND) remain partially discoverable, offering threat actors initial vectors for exploit research.
2. **Internal Network Visibility:** Local host enumeration identified legacy services (SMB/NetBIOS and UPnP) active across endpoints, underscoring the necessity of strict host isolation and network segmentation even within internal trust zones.
3. **Defense-in-Depth Posture:** Addressing minor metadata leakages and enforcing strict service segregation significantly raises the effort required for an external adversary to gain a foothold or pivot laterally.

By applying continuous attack surface management and systematically remediating information leakage, organizations can dramatically shrink their discoverable perimeter.

---

## 8. Evidence & Artifacts

### 8.1 Multi-Vector Footprinting Evidence (Module 1)

#### WHOIS Query Output (`whois networkwalks.com`)
*Shows domain registration, GoDaddy registrar, and HostGator nameservers.*
![WHOIS Query Result](assets/pm1/task1_whois.png)

#### WhatWeb Technology Fingerprint (`whatweb networkwalks.com`)
*Shows WordPress 7.0.4, WP Download Manager 3.3.58, Apache, and target IP.*
![WhatWeb Query Result](assets/pm1/task2_whatweb.png)

#### Nslookup DNS Resolution (`nslookup networkwalks.com`)
*Resolves domain directly to IP 192.232.216.135.*
![nslookup Result](assets/pm1/task3_nslookup.png)

#### cURL Response Headers (`curl -I https://networkwalks.com`)
*Shows HTTP headers, Apache server, WordPress cache, and REST API link (session token sanitized).*
![curl Header Analysis](assets/pm1/task4_curl_headers.png)

#### DNSRecon Enumeration (`dnsrecon -d networkwalks.com`)
*Shows SOA, NS records, BIND version 9.16.23-RH, MX record, and SPF.*
![dnsrecon Result](assets/pm1/task5_dnsrecon.png)

#### Wafw00f WAF Detection (`wafw00f networkwalks.com`)
*Confirms ModSecurity (SpiderLabs) Web Application Firewall.*
![wafw00f WAF Detection](assets/pm1/task6_wafw00f.png)

---

### 8.2 Maltego Visual OSINT Evidence (Module 3)

#### Maltego Data Hub & Transform Hub Setup
*Maltego Graph 4.12.1 setup with OSINT transforms and partner integrations.*
![Maltego Data Hub Setup](assets/pm3/maltego_data_hub.png)

#### Maltego Email Harvesting on `microsoft.com` (Lab Demo)
*Demonstration of email extraction transforms on a large corporate domain.*
![Maltego Graph Microsoft Recon](assets/pm3/maltego_microsoft_recon.png)

#### Maltego Domain-to-Contact Linkage on `networkwalks.com`
*Graph mapping associating domain node with info@networkwalks.com contact.*
![Maltego Graph NetworkWalks Recon](assets/pm3/maltego_networkwalks_recon.png)

---

### 8.3 theHarvester Passive OSINT Evidence (Module 4)

#### Subdomain Enumeration via Baidu Search Engine
*Passive harvest of 8 subdomains without generating direct traffic on the target.*
![theHarvester Baidu Scan](assets/pm4/theharvester_baidu_scan.png)

#### Multi-Source Engine Passive Scan (`-b all`)
*theHarvester query across all search engines and threat intel API checks.*
![theHarvester All Sources Scan](assets/pm4/theharvester_all_sources.png)

---

### 8.4 Zenmap & Nmap Local Network Scanning Evidence (Module 5)

#### Zenmap Subnet Quick Scan (`192.168.64.0/24`)
*Discovered 3 live hosts: Gateway (.1), Web server (.2), and Windows host (.10) (Hardware MACs sanitized).*
![Zenmap Quick Scan](assets/pm5/zenmap_quick_scan.png)

#### Windows Host Network Configuration & `ipconfig /all` Correlation
*Local interface details confirming IP 192.168.64.10 and open NetBIOS/SMB services (Hardware MACs, IPv6, and user paths sanitized).*
![Zenmap and ipconfig correlation](assets/pm5/zenmap_ipconfig_correlation.png)

---

## -End-

👤 **Assessor**  
**dr-winner**  
Assessment: **OSINT & Network Reconnaissance Assessment**  
Repository: [osint-and-network-recon-assessment](https://github.com/dr-winner/osint-and-network-recon-assessment)
