# Data

Sample data and documentation for the Cowrie honeypot capture dataset.

---

## Directory Structure

```
data/
├── README.md              — This file
└── sample/
    └── cowrie-sample-10events.json  — 10 sanitized real events (one per type)
```

---

## Sample Data

`sample/cowrie-sample-10events.json` contains 10 representative events from the live capture, sanitized for public distribution. One event per Cowrie event type, plus an additional SSH key implant command.

**Sanitization applied:**
- Source IPs replaced with `198.51.100.x` (RFC 5737 documentation range)
- All other fields preserved as-is from the live capture

**Event types included:**

| Event | Description |
|-------|-------------|
| `cowrie.session.connect` | New SSH connection established |
| `cowrie.client.version` | SSH client version string |
| `cowrie.client.kex` | SSH HASSH key exchange fingerprint |
| `cowrie.login.failed` | Failed credential attempt |
| `cowrie.login.success` | Accepted credential (honeypot login) |
| `cowrie.command.input` | Command typed in fake shell |
| `cowrie.session.closed` | Session termination with duration |
| `cowrie.command.input` | SSH key implant command (bonus event) |

**Sample event (cowrie.login.success):**
```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "RASYAXINSA8VCPU32GBAMD",
  "message": "login attempt [root/RASYAXINSA8VCPU32GBAMD] succeeded",
  "src_ip": "198.51.100.x",
  "session": "283dc4b9f598",
  "protocol": "ssh",
  "src_country": "Bulgaria",
  "src_country_code": "BG",
  "src_city": "Unknown",
  "src_asn": "AS214209",
  "src_org": "Internet Magnate (Pty) Ltd",
  "timestamp": "2026-05-22T00:00:55.886990Z"
}
```

---

## Full Dataset

The complete 7-day capture dataset is not committed to this repository — it contains ~500MB of raw JSON with real attacker IP addresses and is too large for GitHub.

**Dataset location:** Ubuntu Server `192.168.10.4`

| File | Location | Contents |
|------|----------|---------|
| Raw Cowrie events | `/opt/cowrie-logs/cowrie.json` | All events, append-only |
| GeoIP enriched | `/opt/cowrie-logs/cowrie_enriched.json` | With country/ASN fields |
| nginx logs | `/opt/cowrie-logs/nginx/access.log` | Web attack requests |
| Dionaea logs | `/opt/cowrie-logs/dionaea/dionaea.log` | Malware capture events |
| Wazuh export | `/opt/cowrie-logs/wazuh/wazuh-cowrie.json` | Normalized for SIEM |

---

## Cowrie JSON Schema

Every Cowrie event follows this base schema, with additional fields depending on event type:

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

### Event-Specific Fields

**`cowrie.login.failed` / `cowrie.login.success`**
- `username` — attempted username
- `password` — attempted password

**`cowrie.command.input`**
- `input` — exact command typed by attacker

**`cowrie.client.kex`**
- `hassh` — MD5 fingerprint of SSH client capabilities
- `hasshAlgorithms` — full algorithm string used to compute HASSH

**`cowrie.session.closed`**
- `duration` — session length in seconds

---

## Capture Statistics (7-Day Capture: May 21–28, 2026)

| Metric | Value |
|--------|-------|
| Capture start | May 21, 2026 18:14 UTC |
| Capture end | May 28, 2026 18:14 UTC |
| Total events | TBD |
| Unique source IPs | TBD |
| Countries represented | 50+ |
| Successful logins | TBD |
| Unique HASSH fingerprints | 19+ |
| SSH key implant sessions | 236+ |

> First-hour baseline: 1,076 events from 10 countries within 60 minutes of going live.
