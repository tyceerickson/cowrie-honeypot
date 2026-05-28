# Data

Sample data, live data landing zone, and documentation for the Cowrie honeypot capture dataset.

---

## Directory Structure

```
data/
├── README.md                        — This file
├── live/                            — Live capture data (gitignored, not committed)
│   ├── opensearch_full.json         — Full 11.6M event OpenSearch export (18.59GB)
│   ├── opensearch_enriched.json     — GeoIP-enriched full export
│   ├── cowrie_enriched.json         — Synced from Ubuntu Server
│   ├── nginx_access.log             — Synced nginx web attack log
│   └── .gitkeep                     — Keeps directory tracked by git
└── sample/
    └── cowrie-sample-10events.json  — 10 sanitized real events (one per type)
```

---

## `data/live/` — Live Data Landing Zone

This directory is the local working copy of the live capture data synced from Ubuntu Server. It is listed in `.gitignore` so the actual log files are never committed — they are too large (18.59GB for the full export) and contain real attacker IP addresses.

**Sync from Ubuntu Server:**

```powershell
# ALIENWARE (PowerShell) — from project root
cd C:\TyceErickson\Projects\honeypot-deployment

# Pull enriched log and nginx log from Ubuntu Server
scp terickson@100.82.166.75:/opt/cowrie-logs/cowrie_enriched.json data\live\cowrie_enriched.json
scp terickson@100.82.166.75:/opt/cowrie-logs/nginx/access.log data\live\nginx_access.log

# For full OpenSearch export (11.6M events, 18.59GB):
scp terickson@100.82.166.75:/opt/cowrie-logs/opensearch_full.json data\live\opensearch_full.json
```

Once synced, run analysis scripts pointing to `data\live\`:

```powershell
# Full dataset analysis
python analysis\analyze_opensearch.py `
  --input data\live\opensearch_full.json `
  --output-dir results

# LLM session explanations
python analysis\explain_sessions.py `
  --input data\live\opensearch_enriched.json `
  --nginx-input data\live\nginx_access.log `
  --output-dir results `
  --ollama-url http://100.72.171.104:11434/api/generate
```

---

## `data/sample/` — Sanitized Sample Data

`sample/cowrie-sample-10events.json` contains 10 representative events from the live capture, sanitized for public distribution.

**Sanitization applied:**
- Source IPs replaced with `198.51.100.x` (RFC 5737 documentation range)
- All other fields preserved as-is from the live capture (May 21–28, 2026)

**Event types included:**

| Event | Description |
|-------|-------------|
| `cowrie.session.connect` | New SSH connection established |
| `cowrie.client.version` | SSH client version string |
| `cowrie.client.kex` | SSH HASSH key exchange fingerprint |
| `cowrie.login.failed` | Failed credential attempt |
| `cowrie.login.success` | Accepted credential (honeypot login) |
| `cowrie.command.input` | System reconnaissance (`uname -a`) |
| `cowrie.command.input` | SSH key backdoor implant attempt |
| `cowrie.session.closed` | Session termination with duration |

---

## Full Dataset

The complete 7-day capture dataset lives on Ubuntu Server (`192.168.10.4`) and in OpenSearch.
It is not committed to this repository — use `data/live/` as the local working copy.

| File | Location | Contents |
|------|----------|---------|
| Raw Cowrie events | `/opt/cowrie-logs/cowrie.json` | All events, append-only |
| GeoIP enriched | `/opt/cowrie-logs/cowrie_enriched.json` | With country/ASN fields |
| nginx logs | `/opt/cowrie-logs/nginx/access.log` | Web attack requests |
| Dionaea logs | `/opt/cowrie-logs/dionaea/dionaea.log` | Malware capture events |
| Wazuh export | `/opt/cowrie-logs/wazuh/wazuh-cowrie.json` | Normalized for SIEM |
| OpenSearch export | `/opt/cowrie-logs/opensearch_full.json` | Full 11.6M event dataset (18.59GB) |
| OpenSearch enriched | `/opt/cowrie-logs/opensearch_enriched.json` | GeoIP-enriched full dataset |

---

## Cowrie JSON Schema

### Base Fields (all events)

| Field | Type | Description |
|-------|------|-------------|
| `eventid` | string | Event type identifier |
| `timestamp` | string | ISO8601 UTC timestamp |
| `session` | string | Session ID — links all events in one connection |
| `src_ip` | string | Attacker source IP |
| `protocol` | string | `ssh` or `telnet` |
| `sensor` | string | Cowrie container ID |
| `message` | string | Human-readable event description |

### GeoIP Fields (added by `pipeline/enrich_logs.py`)

| Field | Type | Example |
|-------|------|---------|
| `src_country` | string | `"Singapore"` |
| `src_country_code` | string | `"SG"` |
| `src_city` | string | `"Central"` |
| `src_asn` | string | `"AS45102"` |
| `src_org` | string | `"Alibaba (US) Technology Co."` |

### OpenSearch/Wazuh Field Structure

When events are exported from OpenSearch (via `analyze_opensearch.py`), they are wrapped in Wazuh's schema:

| Field | Contents |
|-------|---------|
| `data.eventid` | Cowrie event type |
| `data.src_ip` | Attacker IP |
| `data.session` | Session ID |
| `data.hassh` | HASSH fingerprint |
| `data.username` | Attempted username |
| `data.password` | Attempted password |
| `data.input` | Command executed |
| `rule.level` | Wazuh alert severity (3–12) |
| `rule.description` | Alert description |
| `full_log` | Raw Cowrie JSON string |
| `@timestamp` | Wazuh ingestion timestamp |

---

## Capture Statistics (7-Day Capture: May 21–28, 2026)

| Metric | Value |
|--------|-------|
| Capture start | May 21, 2026 18:14 UTC |
| Capture end | May 28, 2026 15:28 UTC |
| Total events (OpenSearch) | 11,611,908 |
| Dataset size | 18.59 GB |
| Unique source IPs | 1,321 |
| Countries represented | 105 |
| Successful logins | 5,358 |
| Failed login attempts | 873,373 |
| Commands executed | 501,689 |
| Malware download attempts | 165,580 |
| Web attack requests (nginx) | 6,225 |
| Unique HASSH fingerprints | 51 |
| Unique credential pairs | 4,072 |

> First-hour baseline: 1,076 events from 10 countries within 60 minutes of going live.
