# Data

Sample data, live data landing zone, and documentation for the Cowrie honeypot capture dataset.

---

## Directory Structure

```
data/
├── README.md                        — This file
├── live/                            — Live capture data (gitignored, not committed)
│   ├── cowrie_enriched.json         — Synced from Ubuntu Server for local analysis
│   ├── nginx_access.log             — Synced nginx web attack log
│   ├── opensearch_full.json         — Full Wazuh export from OpenSearch (for analyze_opensearch.py)
│   └── .gitkeep                     — Keeps directory tracked by git
└── sample/
    └── cowrie-sample-10events.json  — 10 sanitized real events (one per type, May 21-28, 2026)
```

---

## `data/live/` — Live Data Landing Zone

This directory is the local working copy of the live capture data synced from Ubuntu Server. It is listed in `.gitignore` so the actual log files are never committed — they are too large (~500MB+).

**Sync from Ubuntu Server (run after capture ends May 28):**

```powershell
# ALIENWARE (PowerShell) — from project root
cd C:\Users\tycee\honeypot-deployment

scp terickson@100.82.166.75:/opt/cowrie-logs/cowrie_enriched.json data\live\cowrie_enriched.json
scp terickson@100.82.166.75:/opt/cowrie-logs/nginx/access.log data\live\nginx_access.log
scp terickson@100.82.166.75:/opt/cowrie-logs/dionaea/dionaea.log data\live\dionaea.log

# For full OpenSearch export (11.6M events):
scp terickson@100.82.166.75:/path/to/opensearch_full.json data\live\opensearch_full.json
```

Once synced, run analysis scripts pointing to `data\live\`:

```powershell
python analysis\explain_sessions.py `
  --input data\live\cowrie_enriched.json `
  --nginx-input data\live\nginx_access.log `
  --output-dir results
```

---

## `data/sample/` — Sanitized Sample Data

`sample/cowrie-sample-10events.json` contains 10 representative events from the live capture, sanitized for public distribution. One event per major Cowrie event type, plus SSH key implant and malware download examples.

**Sanitization applied:**
- Source IPs replaced with `198.51.100.x` (RFC 5737 documentation range)
- All other fields preserved as-is from the live capture (May 21-28, 2026)

**Event types included:**

| Event | Description |
|-------|-------------|
| `cowrie.session.connect` | New SSH connection established |
| `cowrie.client.version` | SSH client version string |
| `cowrie.client.kex` | SSH HASSH key exchange fingerprint |
| `cowrie.login.failed` | Failed credential attempt (x2) |
| `cowrie.login.success` | Accepted credential (honeypot login) |
| `cowrie.command.input` | System reconnaissance (`uname -a`) |
| `cowrie.command.input` | SSH key backdoor implant attempt |
| `cowrie.command.input` | Malware download attempt (`wget`) |
| `cowrie.session.closed` | Session termination with duration |

---

## Full Dataset

The complete 7-day capture dataset lives on Ubuntu Server (`192.168.10.4`).
It is not committed to this repository — use `data/live/` as the local working copy.

| File | Location on Ubuntu Server | Contents |
|------|--------------------------|---------|
| Raw Cowrie events | `/opt/cowrie-logs/cowrie.json` | All events, append-only |
| GeoIP enriched | `/opt/cowrie-logs/cowrie_enriched.json` | With country/ASN fields |
| nginx logs | `/opt/cowrie-logs/nginx/access.log` | Web attack requests |
| Dionaea logs | `/opt/cowrie-logs/dionaea/dionaea.log` | Malware capture events |
| Wazuh export | `/opt/cowrie-logs/wazuh/wazuh-cowrie.json` | Normalized for SIEM |
| OpenSearch export | `/var/lib/wazuh/api/files/` | Full Wazuh dataset (11.6M events) |

---

## Cowrie JSON Schema

Every Cowrie event follows this base schema:

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

---

## Capture Statistics (7-Day Capture: May 21–28, 2026)

| Metric | Value |
|--------|-------|
| Capture start | May 21, 2026 18:14 UTC |
| Capture end | May 28, 2026 18:14 UTC |
| Total events | 11,611,908 |
| Unique source IPs | 1,321 |
| Countries represented | 105 |
| Successful logins | 5,358 |
| Failed login attempts | 873,373 |
| Commands executed | 501,689 |
| Malware download attempts | 165,580 |
| Web attack requests (nginx) | 6,225 |
| Unique HASSH fingerprints | 51 |
| Unique credential pairs | 428,942 |

> **First-hour baseline:** 1,076 events from 10 countries within 60 minutes of going live.
