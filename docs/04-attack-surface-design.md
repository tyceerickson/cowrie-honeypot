# 04 — Attack Surface Design

## Purpose

This document explains the deliberate design decisions behind every service exposed on the honeypot, what category of attacker behavior each service attracts, what data type it produces, and how the combined attack surface creates a multi-layered dataset for security analysis.

---

## Design Philosophy

The honeypot is not a single service. It is a deliberate multi-protocol attack surface designed to attract distinct categories of threat actors simultaneously. Each service was selected because it:

1. Represents a protocol commonly targeted by real-world attackers
2. Produces a fundamentally different data type from the others
3. Maps to a distinct phase of the MITRE ATT&CK framework
4. Generates data that is immediately useful for the Project 4 SIEM pipeline

The combination of SSH behavioral data, web attack signatures, and malware binary captures creates a dataset that no single honeypot type could produce alone.

---

## Service 1 — Cowrie (SSH/Telnet)

### Why SSH and Telnet

SSH (port 22) is the most heavily scanned port on the internet. Every public IP receives SSH credential brute force attempts within hours, sometimes within minutes, of exposure. This makes it the highest-density source of real attack data available without any special configuration.

Telnet (port 23) attracts a distinct attacker population: IoT botnets and legacy system scanners. Many automated botnets (Mirai variants, Mozi derivatives) specifically target Telnet because a large installed base of IoT devices (routers, cameras, DVRs) still run Telnet with default credentials. Telnet data is qualitatively different from SSH data, it tends to be more automated, more botnet-sourced, and involves different credential dictionaries.

Running both services simultaneously on one honeypot allows direct comparison of these two attack populations in a shared timeframe.

### What Cowrie Captures

| Data Type | Description | MITRE Phase |
|-----------|-------------|-------------|
| Connection metadata | Source IP, port, timestamp, protocol | T1046 — Network Service Discovery |
| SSH client fingerprint (HASSH) | Cryptographic hash of client capabilities — fingerprints the tool used | T1046 |
| Credential attempts | Every username/password combination tried, in order | T1110.001 — Brute Force: Password Guessing |
| Session transcripts | Every command typed after login, with timestamps | T1059 — Command and Scripting Interpreter |
| File transfer attempts | wget/curl commands, SFTP uploads | T1105 — Ingress Tool Transfer |
| Environment commands | uname, cat /etc/passwd, id, whoami | T1082 — System Information Discovery |
| Persistence attempts | crontab, /etc/rc.local modifications | T1053 — Scheduled Task/Job |

### Cowrie Configuration

- **Container image:** `cowrie/cowrie:latest` (v2.9.19)
- **Ports:** 22 (SSH) → 2222 internal, 23 (Telnet) → 2223 internal
- **Fake hostname presented to attackers:** `svr04`
- **Fake OS banner:** Debian GNU/Linux
- **Running as:** UID 999 (cowrie user, non-root)
- **Volume mount:** `./logs:/cowrie/cowrie-git/var/log/cowrie` (critical path — not the default)
- **Credentials accepted:** Cowrie uses a default userdb that accepts common credentials including `root/password`, `root/123456`, `admin/admin`, etc.
- **Fake filesystem:** Cowrie presents a simulated Linux filesystem. Commands like `ls`, `cat /etc/passwd`, `uname`, `id` return realistic but fake output.

### Expected Attacker Behavior

**Automated scanners (majority of traffic):** Connect, attempt a short credential list (typically 1–10 passwords), disconnect within seconds. These are automated tools (Mirai variants, custom Python scripts, Masscan+Hydra pipelines) scanning entire IP ranges systematically.

**Semi-automated credential stuffers:** Connect, attempt large wordlists (hundreds to thousands of passwords), often using Hydra or Medusa. Recognizable by regular inter-attempt timing and structured username/password ordering.

**Human operators (rare but high-value):** Connect after a successful login, run reconnaissance commands (`uname -a`, `cat /etc/passwd`, `ps aux`), attempt to download tools (`wget http://...`), attempt persistence. These sessions produce the richest data.

---

## Service 2 — nginx (HTTP/HTTPS)

### Why HTTP/HTTPS

Web servers are the second-most targeted service class after SSH. Any public IP running a web server is automatically indexed by Shodan, Censys, and commercial vulnerability scanners within hours. Web scanning traffic has completely different characteristics from SSH scanning:

- High volume of distinct paths (vulnerability probes)
- User-agent strings that identify specific tools (Nuclei, Shodan, masscan, sqlmap)
- CVE-specific probe patterns that allow exact identification of what exploit is being attempted
- Bot traffic that reveals botnet C2 infrastructure via referrers and payloads

### What nginx Captures

| Data Type | Description | MITRE Phase |
|-----------|-------------|-------------|
| Scanner identification | User-agent strings identify specific tools | T1046 — Network Service Discovery |
| CVE probe paths | `/cgi-bin/`, `/.env`, `/wp-login.php`, `/.git/config` | T1190 — Exploit Public-Facing Application |
| Log4Shell attempts | `${jndi:ldap://...}` in headers and paths | T1190 |
| Path traversal | `../../../etc/passwd` variations | T1083 — File and Directory Discovery |
| Web shell uploads | POST requests to executable paths | T1505.003 — Server Software Component: Web Shell |
| Credential stuffing | POST requests to `/admin`, `/login`, `/wp-login.php` | T1110 — Brute Force |

### nginx Configuration

- **Container image:** `nginx:alpine`
- **Ports:** 80 (HTTP), 443 (HTTPS)
- **Configuration:** Default nginx — intentional. The default config presents as a generic web server, maximizing attacker surface. A custom config would reduce the probe variety.
- **Log format:** Combined access log (IP, timestamp, method, path, status, size, referer, user-agent)
- **Log location:** `./nginx-logs/access.log`, `./nginx-logs/error.log`

### Why Default nginx Config

A hardened nginx config with path restrictions would reduce the attack surface and produce less interesting data. The default config accepts all requests and logs them all, exactly what a honeypot needs. The 404 responses to malicious paths are less important than the fact that every probe is logged.

---

## Service 3 — Dionaea (Malware/Exploit Capture)

### Why SMB, FTP, MSSQL, MySQL

Dionaea emulates the Windows network services that automated malware specifically targets. These services were chosen because:

**SMB (port 445):** The highest-value malware capture surface. EternalBlue (MS17-010) exploits against SMB were used by WannaCry, NotPetya, and are still active in the wild years later. Dionaea captures the actual shellcode payloads from exploit attempts, producing binary artifacts for analysis.

**FTP (port 21):** Malware delivery mechanism. Many botnets and ransomware families use FTP to upload their payloads to compromised hosts. A listening FTP server captures upload attempts and in some cases the actual malware binaries.

**MSSQL (port 1433):** Targeted by database-focused attack campaigns, ransomware precursors, and credential stuffing tools. Produces database credential logs distinct from SSH credentials.

**MySQL (port 3306):** Similar to MSSQL — targets database infrastructure. Also targeted by cryptomining malware that specifically looks for exposed MySQL instances to hijack for persistence.

### What Dionaea Captures

| Data Type | Description | MITRE Phase |
|-----------|-------------|-------------|
| SMB exploit payloads | Raw shellcode from EternalBlue attempts | T1210 — Exploitation of Remote Services |
| Malware binaries | Actual malware files uploaded via FTP/SMB | T1105 — Ingress Tool Transfer |
| Database credentials | Username/password attempts against MSSQL/MySQL | T1110 — Brute Force |
| Protocol fingerprints | SMB negotiate requests, dialect versions | T1046 — Network Service Discovery |
| Download incidents | When Dionaea fetches a malware binary from attacker C2 | T1105 |

### Dionaea Configuration

- **Container image:** `dinotools/dionaea`
- **Ports:** 21 (FTP), 445 (SMB), 1433 (MSSQL), 3306 (MySQL)
- **Log location:** `./dionaea-logs/dionaea.log`, `./dionaea-logs/dionaea-errors.log`
- **Malware capture:** `./dionaea-malware/` (binaries saved here when captured)
- **Note:** Dionaea's log format is a custom text format, not JSON. Analysis requires different parsing than Cowrie.

---

## Combined Attack Surface Map

```
Internet
    │
    ├── Port 22  → Cowrie SSH  → Credential attacks, session transcripts
    ├── Port 23  → Cowrie Telnet → IoT botnet attacks, Telnet credentials
    ├── Port 80  → nginx HTTP  → Web scanners, CVE probes, path traversal
    ├── Port 443 → nginx HTTPS → HTTPS scanners, encrypted web attacks
    ├── Port 21  → Dionaea FTP → Malware upload attempts
    ├── Port 445 → Dionaea SMB → EternalBlue, WannaCry, ransomware
    ├── Port 1433→ Dionaea MSSQL→ Database credential attacks
    └── Port 3306→ Dionaea MySQL→ Database credential attacks, cryptominer probes
```

---

## Why NYC1 Region

DigitalOcean NYC1 was selected specifically because it is one of the most heavily scanned cloud regions. NYC1 IP ranges are well-known to automated scanners and Shodan indexes them aggressively. A new IP in NYC1 is typically indexed by Shodan within 2–6 hours and begins receiving automated attack traffic within the same window.

A less popular region would produce less data in the same timeframe. For a 7-day capture window, NYC1 maximizes data volume.

---

## Attacker Population Taxonomy

Based on Cowrie's HASSH fingerprinting and behavioral patterns, attack traffic falls into these categories:

| Category | % of Traffic | Characteristics | Tool Fingerprint |
|----------|-------------|-----------------|-----------------|
| Automated credential scanners | ~70% | Short sessions, few passwords, no post-login activity | Go SSH clients, custom scripts |
| Botnet propagation | ~20% | Default IoT credentials, downloads malware on success | Mirai variants, Mozi |
| Hydra/Medusa brute force | ~8% | Large wordlists, regular timing, many attempts | OpenSSH client HASSH |
| Human operators | ~2% | Post-login reconnaissance, irregular timing | Various SSH clients |

The 2% human operator category produces the most interesting data for MITRE ATT&CK mapping, even though it represents a small fraction of total traffic.

---

## Data Volume Expectations

Based on first-hour capture data (1,076 events in 30 minutes):

| Timeframe | Estimated Events | Notes |
|-----------|-----------------|-------|
| 1 hour | ~2,000 | First-hour spike as scanners discover new IP |
| 24 hours | ~10,000–50,000 | Stabilizes after initial discovery |
| 7 days | ~100,000–500,000 | Depends on whether Shodan indexes and botnet traffic |
| Log file size | ~500MB–2GB | JSON lines, compresses well |

Disk capacity on VPS: 20GB free. No capacity risk for a 7-day capture.
