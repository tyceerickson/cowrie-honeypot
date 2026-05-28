# 06 — Analysis Report

> **Status: Complete — Capture period May 21–28, 2026.**
> Full analysis based on 11,611,908 Wazuh alerts from 6-day honeypot capture.
> Dataset exported from OpenSearch and analyzed with `analysis/analyze_opensearch.py`.

---

## Capture Summary

| Metric | Value |
|--------|-------|
| Capture start | May 21, 2026 18:14 UTC |
| Capture end | May 28, 2026 15:28 UTC |
| Duration | 6 days, 21 hours |
| Honeypot location | DigitalOcean NYC1 (174.138.35.11) |
| Services active | Cowrie SSH/Telnet · nginx HTTP/HTTPS · Dionaea FTP/SMB/MSSQL/MySQL |
| Total events (OpenSearch) | 11,611,908 |
| Unique source IPs | 1,321 |
| Countries represented | 105 |
| Total sessions | 2,617,958 |
| Successful logins | 5,358 |
| Failed login attempts | 873,373 |
| Commands executed | 501,689 |
| File downloads attempted | 165,580 |
| File uploads attempted | 5,252 |
| Unique credential pairs | 4,072 |
| Unique HASSH fingerprints | 51 |
| Web attack requests (nginx) | 6,225 |
| Dataset size (OpenSearch export) | 18.59 GB |

### First-Hour Baseline (May 21, 2026 18:14–19:14 UTC)

Within the first 60 minutes of going live:

- **1,076 events** captured
- **10 countries** represented
- **Top attacker:** Hong Kong (464 events, 43% of first-hour traffic)
- **First credential success:** `root/Password1` within 90 seconds of going live
- **First tool identified:** SSH-2.0-Go automated scanner, connected within 90 seconds
- **Final 6-day total:** 11,611,908 events from 105 countries

This baseline demonstrates the density of automated scanning on NYC1 IP ranges. Any public IP is discovered and attacked within minutes, not hours.

---

## Section 1 — Geographic Analysis

### Top Attacker Countries

| Rank | Country | Events | % of Total | Notes |
|------|---------|--------|------------|-------|
| 1 | The Netherlands | 1,579,555 | 13.6% | Pfcloud UG bulletproof hosting (AS197328) |
| 2 | Indonesia | 1,308,487 | 11.3% | Universitas Mataram ASN observed |
| 3 | Germany | 1,308,410 | 11.3% | Hetzner, OVH cloud infrastructure |
| 4 | United States | 1,231,291 | 10.6% | Microsoft Azure, DigitalOcean |
| 5 | Bulgaria | 723,627 | 6.2% | Pfcloud UG (same operator as Netherlands) |
| 6 | Hong Kong | 563,613 | 4.9% | Alibaba Cloud HK |
| 7 | Canada | 417,574 | 3.6% | DigitalOcean Toronto |
| 8 | Singapore | 323,633 | 2.8% | Alibaba Cloud SG |
| 9 | India | 306,532 | 2.6% | Oracle Cloud India (AS31898) |
| 10 | South Korea | 291,989 | 2.5% | LG DACOM Corporation |

**Key observation:** The Netherlands and Bulgaria combined account for 19.8% of all traffic — both dominated by Pfcloud UG (AS197328), a bulletproof hosting provider known for tolerating malicious activity. This is not Dutch or Bulgarian attackers — it is global threat actors renting infrastructure in permissive hosting environments.

Geographic blocking is ineffective against this pattern: the same operator (Pfcloud UG) appears under two different countries, and blocking the Netherlands would also block significant legitimate traffic while attackers simply switch to a different ASN.

### Top Attacker ASNs

| Rank | ASN | Organization | Country | Events |
|------|-----|-------------|---------|--------|
| 1 | AS197328 | Pfcloud UG | Netherlands/Bulgaria | ~2,303,182 |
| 2 | AS14061 | DigitalOcean | United States/Canada | ~755,590 |
| 3 | AS45102 | Alibaba Cloud | Hong Kong/Singapore | ~887,246 |
| 4 | AS31898 | Oracle Corporation | India/Global | ~306,532 |
| 5 | AS36352 | ColoCrossing | United States | ~400,000+ |

**Observation:** Cloud providers and hosting companies dominate — attacks originate from rented VPS infrastructure, not residential connections. Attackers rent cheap VPS instances in regions with permissive acceptable-use policies. Blocking at the ASN level (e.g., AS197328) is more effective than country-level blocking.

---

## Section 2 — Credential Analysis

### Top Attempted Usernames

| Rank | Username | Attempts |
|------|----------|---------|
| 1 | root | ~700,000+ |
| 2 | 3245gs5662d34 | 161,992 |
| 3 | 345gs5662d34 | 161,584 |
| 4 | admin | 14,169 |
| 5 | ubuntu | ~8,000+ |
| 6 | user | ~5,000+ |
| 7 | pi | ~3,000+ |
| 8 | test | ~2,500+ |
| 9 | oracle | ~2,000+ |
| 10 | postgres | ~1,500+ |

**Finding:** `root` dominates username attempts as expected. The appearance of `3245gs5662d34` and `345gs5662d34` as high-volume usernames — not just passwords — confirms these are botnet-specific identifiers used as both username AND password, a characteristic fingerprint of the coordinated campaign.

### Top Attempted Passwords

| Rank | Password | Attempts |
|------|----------|---------|
| 1 | 3245gs5662d34 | 161,992 |
| 2 | 345gs5662d34 | 161,584 |
| 3 | 123456 | 81,652 |
| 4 | 123 | 30,060 |
| 5 | 1234 | 22,809 |
| 6 | 1 | 16,957 |
| 7 | password | 15,754 |
| 8 | 12345678 | 15,448 |
| 9 | admin | 14,169 |
| 10 | 12345 | 11,888 |

**Finding:** The `3245gs5662d34` / `345gs5662d34` pair representing 323,576 combined attempts (37% of all credential traffic) is the signature of a single coordinated botnet campaign. These are not common passwords — they are botnet-specific tokens used to identify infected hosts in the attacker's infrastructure. Any server that accepted these credentials is now part of the botnet.

### Credential Pair Analysis

| Metric | Value |
|--------|-------|
| Total login attempts | 878,731 (873,373 failed + 5,358 successful) |
| Unique credential pairs | 4,072 |
| Login success rate | 0.6% |
| Most common successful credential | root/3245gs5662d34 (161,766 successes) |
| Most common failed credential | 345gs5662d34/345gs5662d34 (161,355 failures) |
| Credential success rate for 3245gs5662d34 | 100% — Cowrie accepts all logins |

---

## Section 3 — Attack Velocity & Timing

### Daily Event Volume

| Date | Events | Notes |
|------|--------|-------|
| May 21 | ~50,000 (partial) | Honeypot went live 18:14 UTC |
| May 22 | Not in OpenSearch | Wazuh ingestion not yet active |
| May 23 | 349,705 | First full day in OpenSearch |
| May 24 | 2,350,405 | Major spike — Shodan indexing likely |
| May 25 | 2,688,520 | Highest volume day |
| May 26 | 1,742,714 | Disk-full incident began (Dionaea) |
| May 27 | 2,675,054 | Recovery after disk cleared |
| May 28 | 1,805,510 | Final capture day (partial) |

**Notable:** May 24–25 saw peak attack volumes, likely reflecting Shodan/Censys indexing the IP and distributing it to scanner networks. The 24-hour delay after deployment before peak volume is consistent with known Shodan indexing intervals.

The disk-full incident on May 25–26 (caused by Dionaea's verbose debug logging filling the 25GB VPS disk) caused a Cowrie logging gap. See `docs/09-lessons-learned.md` for full details.

### Attack Velocity Metrics

| Metric | Value |
|--------|-------|
| Average attacks per minute (24h) | 440.2 |
| Peak attacks per minute | ~2,587,726/day ÷ 1440 = ~1,797/min |
| Avg sessions per day | 2,617,958 ÷ 6 = 436,326 |
| First attack after going live | < 90 seconds |

---

## Section 4 — Tool Fingerprinting (HASSH Analysis)

HASSH (Host and Application SSH Signature) provides a cryptographic fingerprint of the SSH client used by each attacker. 51 distinct tools were identified across 6 days.

| Rank | HASSH | Identified Tool | Sessions | % of Traffic |
|------|-------|----------------|---------|-------------|
| 1 | `f555226df1963d1d3c09daf865abdc9a` | Paramiko 2.x (Python SSH library) | 640,253 | 55.1% |
| 2 | `0a07365cc01fa9fc82608ba4019af499` | Go SSH scanner | 545,398 | 46.9% |
| 3 | `16443846184eafde36765c9bab2f4397` | OpenSSH 9.0–9.7 (post-quantum mlkem) | 46,789 | 4.0% |
| 4 | `03a80b21afa810682a776a7d42e5e6fb` | AsyncSSH (Python async SSH) | 30,769 | 2.6% |
| 5 | `af8223ac9914f509afdadfaf5f7ee94e` | OpenSSH 9.9+ (mlkem768nistp256) | 15,337 | 1.3% |
| 6 | Various | OpenSSH 8.x variants | 11,468 | 1.0% |
| 7–51 | Various | Unknown/unidentified tools | ~10,695+ | ~0.9% |

**Critical finding — Tool concentration:** Paramiko 2.x and the Go SSH scanner together account for 1,185,651 sessions — over one million attacks from just two tool families. This concentration reveals that internet-wide SSH scanning is dominated by a small number of widely-used automated libraries.

**Version string spoofing observed:** Sessions using Paramiko (`f555226d...`) presented as `SSH-2.0-libssh_0.9.6` in their client version string, while the HASSH fingerprint revealed the actual underlying library as Paramiko 2.x. This is an active evasion technique — attackers spoofing their tool identity to bypass version-string-based detection rules. HASSH fingerprinting defeats this evasion because it analyzes the cryptographic algorithm preferences rather than the self-reported version string.

**Post-quantum SSH tools observed:** 62,126 sessions used OpenSSH versions with post-quantum key exchange algorithms (mlkem768x25519, mlkem768nistp256, sntrup761) — confirming that even attack tooling is keeping pace with modern cryptographic standards.

---

## Section 5 — Command Analysis (Post-Login Behavior)

### Top Commands Executed

| Rank | Command | Executions | MITRE Technique |
|------|---------|-----------|----------------|
| 1 | `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 149,509 | T1222 — File Permissions Modification |
| 2 | `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA..." >> .ssh/authorized_keys` | 149,348 | T1098.004 — SSH Authorized Keys |
| 3 | `uname -s -v -n -r -m` | 113,080 | T1082 — System Information Discovery |
| 4 | `echo SHELL_TEST` | 2,497 | T1059 — Command Interpreter |
| 5 | `uname -a` | 2,073 | T1082 — System Information Discovery |
| 6 | `whoami` | 2,034 | T1087 — Account Discovery |
| 7 | `uname -m` | 1,945 | T1082 — System Information Discovery |
| 8 | `cat /proc/cpuinfo \| grep name \| wc -l` | 1,901 | T1082 — Cryptominer CPU recon |
| 9 | `rm -rf /tmp/secure.sh; pkill -9 secure.sh` | 1,821 | T1070 — Indicator Removal |
| 10 | `cat /proc/cpuinfo \| grep name \| head -n 1` | 1,819 | T1082 — Cryptominer CPU recon |

### Dominant Pattern — SSH Key Backdoor Implant Campaign

Commands 1 and 2 represent a single two-step attack sequence that executed **149,000+ times**:

1. `chattr -ia .ssh` — Removes immutable file attributes from the `.ssh` directory, disabling write protection
2. `rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAAB..." >> .ssh/authorized_keys` — Wipes existing SSH keys and installs the attacker's RSA public key

The RSA key comment `mdrfckr` identifies this as a known, tracked campaign with documented activity across multiple honeypots. Any server that accepted the login and wasn't a honeypot now has a persistent backdoor key installed — the attacker can return at any time regardless of password changes.

### Secondary Pattern — Cryptominer Reconnaissance

CPU core count (`cat /proc/cpuinfo | grep name | wc -l`, 1,901 executions) and CPU model queries (1,819 executions) are the standard pre-deployment check run by cryptomining malware to determine if a server is profitable before downloading the miner payload. These commands appeared in sessions that did not proceed to download — the honeypot's simulated hardware may not have passed the profitability threshold.

### Anti-Forensics Pattern

`rm -rf /tmp/secure.sh; pkill -9 secure.sh` (1,821 executions) — cleanup scripts deleting themselves from `/tmp/` after execution, indicating attacker awareness of forensic detection and log analysis.

---

## Section 6 — Web Attack Analysis (nginx)

### Request Summary

| Metric | Value |
|--------|-------|
| Total HTTP/HTTPS requests | 6,225 |
| Unique source IPs | 428 |
| Most active attacker | 185.177.72.24 (1,295 requests) |
| Microsoft Azure IPs in top 10 | 4 of 10 |

### Attack Category Breakdown

| Category | Requests | CVE / Technique |
|----------|---------|----------------|
| `.env` file exposure | 1,127 | T1552.001 — Credentials in Files |
| PHPUnit RCE | 450 | CVE-2017-9841 |
| Admin panel probes | 269 | T1110 — Brute Force |
| Config file exposure | 230 | T1552 — Unsecured Credentials |
| CGI exploits | 109 | T1190 — Exploit Public-Facing Application |
| Git repository exposure | 45 | T1552 — Unsecured Credentials |
| IoT device exploits | 83 | CVE-2021-36260 (Hikvision), CVE-2023-1389 (OpenWRT) |
| Path traversal to shell | 13 | T1083 — File and Directory Discovery |
| WordPress exploits | 32 | T1190 — Plugin vulnerabilities |

### Notable Paths

| Path | Requests | Significance |
|------|---------|-------------|
| `/.env` | 118 | Exposes DB passwords, API keys, secrets |
| `/cgi-bin/luci/;stok=/locale` | 55 | **CVE-2023-1389** — OpenWRT RCE (2023) |
| `/SDK/webLanguage` | 28 | **CVE-2021-36260** — Hikvision camera RCE (2021) |
| `/vendor/phpunit/.../eval-stdin.php` | 78 | **CVE-2017-9841** — PHPUnit RCE (2017) |
| `/cgi-bin/.%2e/.%2e/.%2e/bin/sh` | 13 | Path traversal attempt to execute shell |
| `/.git/config` | 16 | Git repository credential exposure |

**Finding — CVE-specific targeting is fully automated:** The honeypot received probes for CVE-2023-1389 (OpenWRT, disclosed March 2023), CVE-2021-36260 (Hikvision, disclosed September 2021), and CVE-2017-9841 (PHPUnit, disclosed June 2017) within hours of IP assignment. Vulnerabilities disclosed years ago remain actively exploited in 2026. Unpatched systems face ongoing risk regardless of disclosure age.

**Microsoft Azure concentration:** Four of the top 10 nginx attacker IPs are in the `20.x.x.x` Azure range, confirming widespread abuse of major cloud providers for web scanning infrastructure. This makes IP-based blocking ineffective without also blocking legitimate Azure traffic.

### Top Source IPs (nginx)

| IP | Requests | Organization |
|----|---------|-------------|
| 185.177.72.24 | 1,295 | Aggressive `.env` scanner |
| 4.228.83.111 | 365 | Microsoft Azure |
| 20.116.59.164 | 310 | Microsoft Azure |
| 20.226.17.32 | 254 | Microsoft Azure |
| 45.148.10.159 | 177 | Unknown |

---

## Section 7 — Dionaea Analysis

### Summary

| Metric | Value |
|--------|-------|
| Total log lines | 11,453,314 |
| Meaningful attack incidents | 0 |
| Malware binaries captured | 0 |
| SQLite database entries | 0 |
| Log file size | 1.5 GB |

**Finding:** Dionaea generated 11.4 million log lines but zero meaningful attack incidents. The log consisted entirely of verbose debug output from packet parsing — one attacker connecting to port 1433 (MSSQL) triggered millions of repeated TDS header parsing debug messages at the `scapy` level.

**Interpretation:** SMB (port 445), FTP (port 21), MSSQL (port 1433), and MySQL (port 3306) received significantly less targeted attack traffic than SSH (port 22) during this capture window. This is consistent with threat intelligence showing SSH brute force remains the dominant attack vector against Linux cloud infrastructure.

**Operational impact:** The 1.5GB Dionaea debug log filled the VPS disk on May 25–26, causing a 24–48 hour gap in Cowrie logging. An estimated 1–2 days of SSH data was lost. See `docs/09-lessons-learned.md` for the full post-mortem and fix.

---

## Section 8 — Session Behavior Classification

### Attack Categories Observed

| Category | Sessions | Description |
|----------|---------|-------------|
| SSH key implant campaign | ~149,000 | Coordinated botnet — chattr + authorized_keys backdoor |
| Automated credential scan (no login) | ~2,112,600 | Connected, attempted ≤10 credentials, disconnected |
| Automated credential scan (login) | ~5,358 | Logged in, ran scripted post-login commands |
| Cryptominer reconnaissance | ~3,720 | CPU/memory check before mining deployment |
| System reconnaissance | ~2,073 | uname, whoami, basic enumeration |
| Telnet scanner | ~15 | Telnet with default IoT credentials |
| Web scanner (nginx) | 6,225 | Systematic CVE and path probing |
| Dionaea exploit attempts | 0 | No meaningful SMB/FTP/DB attacks |

---

## Key Findings

1. **A single coordinated botnet ran 149,000+ SSH backdoor implant attempts** — The `chattr -ia .ssh` + `authorized_keys` campaign (RSA key `mdrfckr`) was the dominant post-login activity across all 6 days. Any server running a default SSH configuration that accepted the `3245gs5662d34` credential is now persistently compromised. This campaign ran continuously and showed no degradation over the capture period.

2. **Two tools responsible for 1.18 million sessions** — Paramiko 2.x (640,253 sessions, 55%) and a Go SSH scanner (545,398 sessions, 47%) dominated all traffic. HASSH fingerprinting identified these tools despite active version string spoofing. Blocking HASSH `f555226df1963d1d3c09daf865abdc9a` alone would have eliminated 55% of all attack sessions.

3. **165,580 malware download attempts represent live threat intelligence** — The C2 URLs in `results/file-downloads.csv` are active infrastructure distributing malware as of May 2026. These URLs are directly actionable as blocklist entries for any organization running a similar environment.

4. **Bulletproof hosting dominates attack origin** — Pfcloud UG (AS197328) in the Netherlands and Bulgaria combined for ~2.3 million events (19.8%). Geographic blocking is ineffective; ASN-level blocking is more targeted and would reduce attack volume significantly.

5. **Web attackers are running automated CVE scanners against all new IPs** — CVE-2023-1389 (OpenWRT), CVE-2021-36260 (Hikvision), and CVE-2017-9841 (PHPUnit) all received active probes within hours of the IP being assigned. The 2017 PHPUnit vulnerability received 450 attempts — 9 years after disclosure — confirming that unpatched systems remain at active risk indefinitely.

---

## Defensive Recommendations

Based on observed attack patterns across 11.6 million events:

| Priority | Recommendation | Addresses |
|----------|---------------|---------|
| Critical | Disable SSH password authentication (`PasswordAuthentication no`) | 873,373 credential attempts eliminated |
| Critical | Deploy fail2ban — 3 failures / 24h ban | Blocks all observed brute force patterns |
| High | Block AS197328 (Pfcloud UG) at firewall | Eliminates ~20% of all attack traffic |
| High | Alert on HASSH `f555226df1963d1d3c09daf865abdc9a` | Detects 55% of SSH attack traffic |
| High | Block `3245gs5662d34` and `345gs5662d34` credentials | Eliminates dominant botnet campaign |
| Medium | Patch CVE-2023-1389, CVE-2021-36260 | Closes actively exploited vulnerabilities |
| Medium | Remove PHPUnit from production deployments | Eliminates CVE-2017-9841 attack surface |
| Medium | Restrict `.env`, `.git` path access at web server | Prevents credential file exposure |
| Low | Monitor for `chattr -ia .ssh` command execution | Detects key implant campaign in progress |
