# Diagrams

Architecture and data flow diagrams for the honeypot deployment.

---

## Diagrams

| File | Description | Status |
|------|-------------|--------|
| `architecture-diagram.png` | Full system topology — VPS, WireGuard tunnel, OPNsense, Ubuntu Server, Alienware | ✅ Complete |
| `data-pipeline-diagram.svg` | Log flow from honeypot capture through GeoIP enrichment to Wazuh and analysis | ✅ Complete |
| `attack-timeline-diagram.svg` | Daily attack volume over 6-day capture with annotated key events | ✅ Complete |

---

## Architecture Diagram

![Architecture Diagram](architecture-diagram.png)

Full system topology showing the internet-facing VPS, WireGuard encrypted tunnel, OPNsense firewall, Ubuntu Server log pipeline, and Alienware analysis workstation.

---

## Data Pipeline Diagram

![Data Pipeline Diagram](data-pipeline-diagram.svg)

End-to-end data flow:
1. VPS honeypot services (Cowrie/nginx/Dionaea) write logs continuously
2. rsync syncs logs every 15 minutes through WireGuard tunnel
3. Ubuntu Server runs GeoIP enrichment hourly via `enrich_logs.py`
4. Wazuh agent ingests enriched logs continuously into OpenSearch
5. Alienware pulls the full dataset for analysis and LLM explanation

---

## Attack Timeline Diagram

![Attack Timeline Diagram](attack-timeline-diagram.svg)

Daily attack volumes across the 6-day capture period (May 23–28, 2026):

| Date | Events | Notes |
|------|--------|-------|
| May 23 | 349,705 | First full day — Wazuh indexing starts |
| May 24 | 2,350,405 | Major spike — Shodan/Censys indexing |
| May 25 | 2,688,520 | Peak volume |
| May 26 | 1,742,714 | Dionaea disk-full incident |
| May 27 | 2,675,054 | Recovery after disk cleared |
| May 28 | 1,805,510 | Final partial day |

**Tool breakdown:** Paramiko 2.x (640,253 sessions, 55%) and a Go SSH scanner (545,398 sessions, 47%) together accounted for 1.18 million sessions — over 45% of all traffic from just two tool families.

---

## Architecture Overview (text)

```
Internet Attackers (Global)
│
│  TCP 22/23 · TCP 80/443 · TCP 21/445/1433/3306
▼
┌─────────────────────────────────────────┐
│     DigitalOcean VPS — NYC1             │
│     Cowrie · nginx · Dionaea            │
│     WireGuard Client (10.10.10.2)       │
└──────────────┬──────────────────────────┘
               │ WireGuard UDP encrypted tunnel
               ▼
┌─────────────────────────────────────────┐
│     OPNsense Firewall — home lab        │
│     WireGuard Server (10.10.10.1)       │
│     4 VLANs (10/20/30/40)              │
└──────────────┬──────────────────────────┘
               │ VLAN 10 · 192.168.10.0/24
               ▼
┌─────────────────────────────────────────┐
│     Ubuntu Server — 192.168.10.4        │
│     GeoIP enrichment · Wazuh SIEM       │
│     11,611,908 events indexed           │
└──────────────┬──────────────────────────┘
               │ scp / analysis
               ▼
┌─────────────────────────────────────────┐
│     Alienware m16 R2                    │
│     Python analysis · Ollama LLM        │
│     RTX 4070 · 64GB RAM                 │
└─────────────────────────────────────────┘
```
