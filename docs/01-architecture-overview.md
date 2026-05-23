# 01 — Architecture Overview

## Purpose

This document describes the complete architecture of the internet-facing honeypot deployment built as Project 3 of a 4-project cybersecurity portfolio. The system captures real attacker behavior from the global internet, forwards logs via encrypted tunnel to an on-premises SIEM pipeline, and produces labeled attack data for the Project 4 AI-powered SOC platform.

---

## Design Objectives

| Objective | Implementation |
|-----------|---------------|
| Capture real internet attack data | VPS with public IP exposed on multiple honeypot services |
| Protect home network identity | WireGuard tunnel — home IP never appears in attacker logs |
| Secure management access | Real SSH on port 2222, Tailscale-only, key authentication |
| Automated log pipeline | rsync every 15 minutes via encrypted tunnel to Ubuntu Server |
| SIEM-ready data format | Structured JSON with GeoIP enrichment for Wazuh ingestion |
| Multi-protocol coverage | SSH/Telnet (Cowrie) + HTTP/HTTPS (nginx) + SMB/FTP/DB (Dionaea) |

---

## System Components

### Cloud Infrastructure

| Component | Details |
|-----------|---------|
| **Provider** | DigitalOcean NYC1 |
| **Droplet** | ubuntu-home-server-droplet |
| **Public IP** | 174.138.35.11 |
| **OS** | Ubuntu 24.04.3 LTS (Noble) |
| **CPU** | 1 vCPU |
| **RAM** | 961MB (512MB swap added) |
| **Disk** | 25GB SSD |
| **Cost** | $6.00/month |
| **Tailscale IP** | 100.89.15.57 |
| **WireGuard tunnel IP** | 10.10.10.2/30 |

### Home Lab Infrastructure

| Component | Details |
|-----------|---------|
| **Firewall** | OPNsense — primary security boundary |
| **WireGuard server IP** | 10.10.10.1/30 |
| **Home WAN IP** | 206.174.162.81 (Eero-assigned, behind NAT) |
| **Ubuntu Server** | 192.168.10.4 — VLAN 10, log landing zone |
| **Analysis workstation** | Alienware m16 R2 — Python, Ollama, Jupyter |
| **VLAN structure** | 10 (Management) / 20 (Attackers) / 30 (Victims) / 40 (Cisco) |

---

## Honeypot Services

### Cowrie — SSH/Telnet Honeypot

Cowrie emulates a full SSH and Telnet server. When an attacker connects on port 22 or 23, they receive a realistic login prompt. Common credentials (root/password, admin/admin, etc.) are accepted and the attacker is dropped into a fake Linux shell that responds convincingly to commands. Every credential attempt, every command typed, every file transfer attempted is logged to structured JSON with full session metadata.

- **Container:** `cowrie/cowrie:latest` (version 2.9.19)
- **Ports:** 22 (SSH), 23 (Telnet)
- **Log format:** JSON — one event per line
- **Key fields:** `eventid`, `src_ip`, `username`, `password`, `input`, `session`, `timestamp`
- **Fake hostname:** `svr04`
- **Running as:** UID 999 (cowrie user, non-root)

### nginx — HTTP/HTTPS Honeypot

nginx serves as a web honeypot on ports 80 and 443. The default nginx configuration is intentionally left in place — it presents as a generic web server, attracting automated vulnerability scanners, CVE exploit attempts, path traversal attacks, Log4Shell probes, and WordPress brute force attempts.

- **Container:** `nginx:alpine`
- **Ports:** 80 (HTTP), 443 (HTTPS)
- **Log format:** Combined access log format
- **Key fields:** Remote IP, timestamp, request method, path, status code, user agent

### Dionaea — Malware/Exploit Honeypot

Dionaea emulates vulnerable Windows network services. SMB on port 445 attracts automated worms and exploit frameworks. FTP, MSSQL, and MySQL emulation attracts credential stuffing and data exfiltration attempts. When malware attempts to upload a binary payload, Dionaea captures the actual file.

- **Container:** `dinotools/dionaea`
- **Ports:** 21 (FTP), 445 (SMB), 1433 (MSSQL), 3306 (MySQL)
- **Log format:** Custom text log + binary malware captures
- **Captures:** Shellcode, malware binaries, exploit payloads

---

## Network Architecture

```
INTERNET
         │
         │  TCP 22, 23, 80, 443, 21, 445, 1433, 3306
         ▼
┌─────────────────────────────────────────────────────┐
│  DigitalOcean Cloud Firewall (honeypot-deployment)  │
│                                                     │
│  INBOUND ALLOW:                                     │
│  TCP 22    → All IPv4/IPv6  (Cowrie SSH)            │
│  TCP 23    → All IPv4/IPv6  (Cowrie Telnet)         │
│  TCP 80    → All IPv4/IPv6  (nginx HTTP)            │
│  TCP 443   → All IPv4/IPv6  (nginx HTTPS)           │
│  TCP 21    → All IPv4/IPv6  (Dionaea FTP)           │
│  TCP 445   → All IPv4/IPv6  (Dionaea SMB)           │
│  TCP 1433  → All IPv4/IPv6  (Dionaea MSSQL)         │
│  TCP 3306  → All IPv4/IPv6  (Dionaea MySQL)         │
│  TCP 2222  → 100.72.171.104 (Real SSH, Tailscale)   │
│  UDP 51820 → All IPv4/IPv6  (WireGuard)             │
│  OUTBOUND: All TCP/UDP/ICMP allowed                 │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│  VPS — ubuntu-home-server-droplet (174.138.35.11)   │
│                                                     │
│  Docker containers:                                 │
│  ├── cowrie    (ports 22→2222, 23→2223)             │
│  ├── nginx-honeypot (ports 80→80, 443→443)          │
│  └── dionaea   (ports 21, 445, 1433, 3306)          │
│                                                     │
│  /opt/cowrie/                                       │
│  ├── logs/cowrie.json       (Cowrie events)         │
│  ├── nginx-logs/access.log  (Web requests)          │
│  ├── dionaea-logs/          (Exploit logs)          │
│  └── dionaea-malware/       (Captured binaries)     │
│                                                     │
│  Management:                                        │
│  ├── Real SSH: port 2222 (key-only, Tailscale)      │
│  ├── Tailscale: 100.89.15.57                        │
│  ├── fail2ban: watching port 2222                   │
│  └── iptables: blocks outbound from UID 999         │
│                                                     │
│  WireGuard client (wg0):                            │
│  ├── Tunnel IP: 10.10.10.2/30                       │
│  ├── Peer: OPNsense (10.10.10.1)                    │
│  └── AllowedIPs: 10.10.10.1/32, 192.168.10.0/24    │
└──────────────────────┬──────────────────────────────┘
                       │ UDP 51820 — WireGuard encrypted
                       │ VPS initiates outbound to OPNsense WAN
                       ▼
┌──────────────────────────────────────────────────────┐
│  OPNsense Firewall (192.168.10.1)                    │
│                                                     │
│  WireGuard server (wg-honeypot):                    │
│  ├── Instance: wg0, port 51820                      │
│  ├── Tunnel IP: 10.10.10.1/30                       │
│  └── Peer: ubuntu-home-server-droplet               │
│                                                     │
│  Interface: HoneypotOPT6 (wg0)                      │
│  Firewall rule: OPT6 → VLAN 10 pass                 │
│  (allows log forwarding to Ubuntu Server)           │
│                                                     │
│  Static route on Ubuntu Server:                     │
│  10.10.10.0/30 via 192.168.10.1 dev enp0s2          │
└──────────────────────┬──────────────────────────────┘
                       │ VLAN 10 (192.168.10.0/24)
                       ▼
┌──────────────────────────────────────────────────────┐
│  Ubuntu Server — homeserver (192.168.10.4)           │
│  Tailscale: 100.82.166.75                           │
│                                                     │
│  /opt/cowrie-logs/                                  │
│  ├── cowrie.json              (raw Cowrie events)   │
│  ├── cowrie_enriched.json     (GeoIP enriched)      │
│  ├── nginx/access.log         (web attacks)         │
│  └── dionaea/                 (malware logs)        │
│                                                     │
│  /opt/geoip/                                        │
│  ├── GeoLite2-City.mmdb  (63MB)                     │
│  ├── GeoLite2-ASN.mmdb   (12MB)                     │
│  └── enrich_logs.py      (runs hourly via cron)     │
│                                                     │
│  Cron jobs:                                         │
│  ├── /etc/cron.d/cowrie-sync (rsync, every 15 min) │
│  └── /etc/cron.d/geoip-enrich (enrichment, hourly) │
│                                                     │
│  → Project 4: Wazuh SIEM installation target        │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│  Alienware m16 R2 — Analysis Workstation             │
│  192.168.10.x · Tailscale: 100.72.171.104           │
│  Intel Ultra 9 185H · 64GB RAM · RTX 4070           │
│                                                     │
│  Python analysis pipeline                           │
│  Ollama llama3.1:8b (local LLM, RTX 4070)           │
│  Jupyter notebooks                                  │
│  GitHub — this repository                           │
└──────────────────────────────────────────────────────┘
```

---

## Data Flow Summary

1. Real attacker connects to VPS public IP on any exposed port
2. Appropriate honeypot service (Cowrie/nginx/Dionaea) handles the connection and logs the interaction as structured JSON
3. rsync cron runs every 15 minutes, pushing all logs through the WireGuard tunnel to Ubuntu Server at `/opt/cowrie-logs/`
4. GeoIP enrichment script runs hourly on Ubuntu Server, adding country/city/ASN fields to every event
5. Enriched logs are available for Wazuh SIEM ingestion (Project 4) and Python analysis (this project)

---

## Key Design Decisions

**Why a VPS instead of home lab exposure:** The VPS absorbs all internet attack traffic. The home network IP never appears in any attacker logs. If the honeypot were compromised, the blast radius is limited to the VPS — the home lab is completely isolated.

**Why WireGuard instead of SSH tunnel:** WireGuard is stateless, survives network interruptions, and is natively supported by OPNsense. The VPS initiates the connection outbound, which means the double-NAT behind the Eero router is irrelevant, no port forwarding required on the home network.

**Why OPNsense initiates vs VPS initiates:** The home WAN IP (192.168.4.58) is behind Eero NAT and not directly routable from the internet. The VPS dials out to OPNsense's real public IP (206.174.162.81), not the other way around.

**Why three honeypot services:** Each service captures a fundamentally different attacker profile and data type. Cowrie produces behavioral session data (commands, credentials). nginx produces web attack signatures (CVEs, scanners). Dionaea produces binary artifacts (actual malware). The combination produces three distinct MITRE ATT&CK phase datasets from one deployment.
