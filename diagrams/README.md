# Diagrams

Architecture and data flow diagrams for the Cowrie honeypot deployment.

---

## Planned Diagrams

| File | Description | Status |
|------|-------------|--------|
| `architecture-diagram.png` | Full system topology — VPS, WireGuard tunnel, OPNsense, Ubuntu Server, Alienware | ⏳ Pending |
| `data-pipeline-diagram.png` | Log flow from honeypot capture through enrichment to Wazuh | ⏳ Pending |
| `attack-timeline-diagram.png` | Attack volume visualization over the 7-day capture period | ⏳ Generated after May 28 |

---

## Architecture Overview

The text-based architecture diagram is maintained in `README.md` and `docs/01-architecture-overview.md`. PNG versions will be added here after the capture period ends.

```
Internet Attackers (Global)
         │
         │  TCP 22/23 · TCP 80/443 · TCP 21/445/1433/3306
         ▼
┌─────────────────────────────────────────┐
│     DigitalOcean VPS — NYC1             │
│     174.138.35.11                       │
│     Cowrie · nginx · Dionaea            │
│     WireGuard Client (10.10.10.2)       │
└──────────────┬──────────────────────────┘
               │ WireGuard UDP encrypted tunnel
               ▼
┌─────────────────────────────────────────┐
│     OPNsense Firewall                   │
│     WireGuard Server (10.10.10.1)       │
│     4 VLANs (10/20/30/40)              │
└──────────────┬──────────────────────────┘
               │ VLAN 10
               ▼
┌─────────────────────────────────────────┐
│     Ubuntu Server (192.168.10.4)        │
│     Log landing zone + GeoIP pipeline   │
│     → Wazuh SIEM (Project 4)           │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│     Alienware m16 R2                    │
│     Python analysis · Ollama LLM        │
└─────────────────────────────────────────┘
```

---

## Data Pipeline Flow

```
Attacker connects to VPS port 22/23/80/443/21/445/1433/3306
                    │
                    ▼
         Cowrie / nginx / Dionaea
         logs to /opt/cowrie/logs/
                    │
                    │ rsync every 15 min
                    │ via WireGuard tunnel
                    ▼
         Ubuntu Server
         /opt/cowrie-logs/cowrie.json
                    │
                    │ enrich_logs.py (hourly)
                    ▼
         cowrie_enriched.json
         (+ src_country, src_asn fields)
                    │
          ┌─────────┴──────────┐
          │                    │
          ▼                    ▼
   analyze_sessions.py   export_to_wazuh.py
   results/              /opt/cowrie-logs/wazuh/
   attack-analysis.md    wazuh-cowrie.json
   charts/*.png          → Wazuh SIEM (Project 4)
          │
          ▼
   explain_sessions.py (on Alienware)
   Ollama llama3.1:8b
   results/session-explanations.md
```
