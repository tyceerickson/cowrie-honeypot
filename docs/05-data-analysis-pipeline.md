# 05 — Data Analysis Pipeline

## Overview

This document describes the complete data pipeline from raw honeypot log capture through GeoIP enrichment, storage, and export to the Project 4 Wazuh SIEM. It defines the log schemas for every service, the transformation steps applied, and the final output format consumed by the analysis scripts and downstream SIEM.

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  VPS — 174.138.35.11                                        │
│                                                             │
│  Source logs (written by containers):                       │
│  /opt/cowrie/logs/cowrie.json        ← Cowrie events        │
│  /opt/cowrie/nginx-logs/access.log   ← nginx access log     │
│  /opt/cowrie/nginx-logs/error.log    ← nginx error log      │
│  /opt/cowrie/dionaea-logs/dionaea.log← Dionaea events       │
│  /opt/cowrie/dionaea-malware/        ← Captured binaries    │
│                                                             │
│  Transport: rsync every 15 min via WireGuard tunnel         │
│  Cron: /etc/cron.d/cowrie-sync                              │
└──────────────────────┬──────────────────────────────────────┘
                       │ Encrypted WireGuard tunnel
                       │ rsync -av -e 'ssh -i /root/.ssh/cowrie_sync'
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Ubuntu Server — 192.168.10.4                               │
│                                                             │
│  Landing zone:                                              │
│  /opt/cowrie-logs/cowrie.json        ← raw Cowrie events    │
│  /opt/cowrie-logs/nginx/access.log   ← web attack logs      │
│  /opt/cowrie-logs/dionaea/           ← malware/exploit logs │
│                                                             │
│  Enrichment (hourly cron):                                  │
│  /opt/geoip/enrich_logs.py                                  │
│  Input:  /opt/cowrie-logs/cowrie.json                       │
│  Output: /opt/cowrie-logs/cowrie_enriched.json              │
│                                                             │
│  GeoIP databases:                                           │
│  /opt/geoip/GeoLite2-City.mmdb  (63MB — city-level)        │
│  /opt/geoip/GeoLite2-ASN.mmdb   (12MB — ASN/org lookup)    │
└──────────────────────┬──────────────────────────────────────┘
                       │ SCP/rsync on demand
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Alienware m16 R2 — Analysis Workstation                    │
│                                                             │
│  analysis/analyze_sessions.py  → results/attack-analysis.md│
│  analysis/explain_sessions.py  → results/session-explanations.md│
│  pipeline/export_to_wazuh.py   → Wazuh-formatted JSON      │
└─────────────────────────────────────────────────────────────┘
```

---

## Log Schema — Cowrie (JSON)

Cowrie writes one JSON object per line to `cowrie.json`. Each event has a common base schema plus event-specific fields.

### Base Fields (all events)

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `eventid` | string | `"cowrie.session.connect"` | Event type identifier |
| `timestamp` | string (ISO8601) | `"2026-05-21T18:13:43.277097Z"` | UTC timestamp |
| `session` | string | `"59501bce750e"` | Unique session identifier — links all events in one connection |
| `src_ip` | string | `"47.82.102.10"` | Attacker source IP |
| `sensor` | string | `"1352cccb3762"` | Container ID of Cowrie instance |
| `uuid` | string | `"287e2678-54d7-11f1-..."` | Unique event UUID |
| `protocol` | string | `"ssh"` or `"telnet"` | Protocol for this session |

### Event Types

#### `cowrie.session.connect`
Fired when a new connection is established.

```json
{
  "eventid": "cowrie.session.connect",
  "src_ip": "47.82.102.10",
  "src_port": 45352,
  "dst_ip": "172.18.0.2",
  "dst_port": 2222,
  "session": "59501bce750e",
  "protocol": "ssh",
  "message": "New connection: 47.82.102.10:45352 (172.18.0.2:2222) [session: 59501bce750e]",
  "sensor": "1352cccb3762",
  "uuid": "287e2678-54d7-11f1-9301-966f163ec6f0",
  "timestamp": "2026-05-21T18:13:43.277097Z"
}
```

#### `cowrie.client.version`
SSH client version string — identifies the tool used.

```json
{
  "eventid": "cowrie.client.version",
  "version": "SSH-2.0-Go",
  "message": "Remote SSH version: SSH-2.0-Go",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:43.279022Z"
}
```

#### `cowrie.client.kex`
SSH key exchange fingerprint (HASSH) — cryptographically identifies the SSH client software.

| Field | Description |
|-------|-------------|
| `hassh` | MD5 hash of client capabilities — tool fingerprint |
| `hasshAlgorithms` | Full algorithm list used to compute HASSH |
| `kexAlgs` | Key exchange algorithms supported |
| `encCS` | Encryption ciphers supported |

#### `cowrie.login.failed`
Credential attempt that was rejected.

```json
{
  "eventid": "cowrie.login.failed",
  "username": "root",
  "password": "123456",
  "message": "login attempt [root/123456] failed",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:43.800000Z"
}
```

#### `cowrie.login.success`
Credential attempt that was accepted by Cowrie's userdb.

```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "Password1",
  "message": "login attempt [root/Password1] succeeded",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.105311Z"
}
```

#### `cowrie.command.input`
Command typed in the fake shell after login.

```json
{
  "eventid": "cowrie.command.input",
  "input": "uname -s -v -n -r -m",
  "message": "CMD: uname -s -v -n -r -m",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.583410Z"
}
```

#### `cowrie.session.closed`
Session termination with duration.

```json
{
  "eventid": "cowrie.session.closed",
  "duration": "1.6",
  "message": "Connection lost after 1.6 seconds",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.872963Z"
}
```

### GeoIP-Enriched Fields (added by `enrich_logs.py`)

After enrichment, every event with a `src_ip` field gains:

| Field | Type | Example | Source |
|-------|------|---------|--------|
| `src_country` | string | `"Hong Kong"` | GeoLite2-City |
| `src_country_code` | string | `"HK"` | GeoLite2-City |
| `src_city` | string | `"Central"` | GeoLite2-City |
| `src_asn` | string | `"AS45102"` | GeoLite2-ASN |
| `src_org` | string | `"Alibaba (US) Technology Co., Ltd."` | GeoLite2-ASN |

---

## Log Schema — nginx (Access Log)

nginx uses Combined Log Format:

```
REMOTE_IP - - [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS SIZE "REFERER" "USER_AGENT"
```

Example:
```
185.234.218.96 - - [21/May/2026:18:47:23 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x"
```

| Field | Description | Analysis Value |
|-------|-------------|----------------|
| Remote IP | Attacker source | GeoIP lookup |
| Timestamp | Request time | Timeline analysis |
| Method + Path | What was requested | CVE/scanner identification |
| Status | HTTP response code | Success/failure |
| User Agent | Tool identification | Scanner fingerprinting |

### High-Value Paths to Watch

| Path | Attack Type | MITRE |
|------|-------------|-------|
| `/.env` | Environment file exposure | T1552.001 |
| `/.git/config` | Git repository exposure | T1552 |
| `/wp-login.php` | WordPress brute force | T1110 |
| `/cgi-bin/` | CGI exploit attempts | T1190 |
| `/admin`, `/manager` | Admin panel brute force | T1110 |
| `/actuator` | Spring Boot exposure | T1190 |
| `${jndi:` in headers | Log4Shell (CVE-2021-44228) | T1190 |
| `/../../../etc/passwd` | Path traversal | T1083 |

---

## Log Schema — Dionaea

Dionaea uses a custom text log format. Each line contains a timestamp, module, log level, and message.

```
[21052026 18:51:08] connection /code/src/connection.c:249-debug: connection_bind con 0x... addr ::1 port 53
[21052026 18:51:08] incident /code/src/incident.c:365-debug: incident 0x... dionaea.connection.tcp.listen
```

Key incident types:

| Incident | Description |
|----------|-------------|
| `dionaea.connection.tcp.listen` | Service listening on port |
| `dionaea.connection.tcp.accept` | New inbound connection |
| `dionaea.download.offer` | Attacker attempting to upload a file |
| `dionaea.download.complete` | File download completed (binary captured) |
| `dionaea.modules.python.smb.dcerpc.request` | SMB exploit attempt |

---

## Transport — rsync via WireGuard

### Cron Schedule (`/etc/cron.d/cowrie-sync` on VPS)

```cron
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' /opt/cowrie/logs/cowrie.json terickson@192.168.10.4:/opt/cowrie-logs/
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' /opt/cowrie/nginx-logs/ terickson@192.168.10.4:/opt/cowrie-logs/nginx/
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' /opt/cowrie/dionaea-logs/ terickson@192.168.10.4:/opt/cowrie-logs/dionaea/
```

- **Frequency:** Every 15 minutes
- **Authentication:** ed25519 SSH key (`/root/.ssh/cowrie_sync`) — no password
- **Transport:** SSH over WireGuard tunnel (10.10.10.2 → 192.168.10.4)
- **Mode:** Incremental (`-a`) — only transfers changed bytes
- **Reliability:** rsync handles partial transfers and network interruptions automatically

---

## GeoIP Enrichment

### Script: `pipeline/enrich_logs.py`

Runs hourly on Ubuntu Server via cron. Reads `cowrie.json`, enriches every event that has a `src_ip` field, writes output to `cowrie_enriched.json`.

```bash
# Cron entry (/etc/cron.d/geoip-enrich)
0 * * * * terickson python3 /opt/geoip/enrich_logs.py >> /var/log/geoip-enrich.log 2>&1
```

### First-Hour Results (May 21, 2026)

```
[+] Loading GeoIP databases...
[+] Reading /opt/cowrie-logs/cowrie.json
[+] Enriched 1076 events (0 skipped)
[+] Output written to /opt/cowrie-logs/cowrie_enriched.json

[+] Top 10 attacker countries:
   464 events  Hong Kong
   221 events  Germany
   125 events  Vietnam
   104 events  India
    68 events  Taiwan
    23 events  Japan
    22 events  Brazil
    16 events  United States
    15 events  Bulgaria
     6 events  Indonesia
```

---

## Wazuh Export Schema

The `pipeline/export_to_wazuh.py` script transforms Cowrie's JSON format into Wazuh-compatible syslog JSON for Project 4 ingestion.

### Field Mapping

| Cowrie Field | Wazuh Field | Notes |
|-------------|-------------|-------|
| `src_ip` | `data.src_ip` | Source IP |
| `eventid` | `data.eventid` | Event type |
| `timestamp` | `timestamp` | ISO8601 |
| `session` | `data.session_id` | Session correlation |
| `username` | `data.username` | Credential data |
| `password` | `data.password` | Credential data |
| `input` | `data.command` | Command transcript |
| `src_country` | `data.geoip.country_name` | GeoIP enrichment |
| `src_asn` | `data.geoip.asn` | ASN enrichment |
| `protocol` | `data.protocol` | ssh/telnet |

### Wazuh Decoder Target

Wazuh has a native Cowrie decoder. The export script formats events to match the expected decoder input, enabling automatic rule matching and alert generation without custom decoder development.

---

## Log Storage Locations

### VPS (`174.138.35.11`)

| Path | Contents | Retention |
|------|----------|-----------|
| `/opt/cowrie/logs/cowrie.json` | Live Cowrie events (append-only) | 7 days + logrotate |
| `/opt/cowrie/nginx-logs/access.log` | nginx access log | 7 days + logrotate |
| `/opt/cowrie/nginx-logs/error.log` | nginx error log | 7 days + logrotate |
| `/opt/cowrie/dionaea-logs/dionaea.log` | Dionaea events | 7 days + logrotate |
| `/opt/cowrie/dionaea-malware/` | Captured malware binaries | Permanent |

### Ubuntu Server (`192.168.10.4`)

| Path | Contents |
|------|----------|
| `/opt/cowrie-logs/cowrie.json` | Synced raw Cowrie events |
| `/opt/cowrie-logs/cowrie_enriched.json` | GeoIP-enriched events |
| `/opt/cowrie-logs/nginx/access.log` | Synced nginx logs |
| `/opt/cowrie-logs/dionaea/dionaea.log` | Synced Dionaea logs |

---

## Log Rotation

Logrotate configured on VPS (`/etc/logrotate.d/cowrie`):

```
/opt/cowrie/logs/cowrie.json {
    daily
    rotate 7
    compress
    delaycompress
    copytruncate
    missingok
    notifempty
}
```

`copytruncate` is used instead of `create` to avoid interrupting the running Docker container's file handle.

---

## Status Check During Data Gathering

Run this command in the homeserver to get an snapshot on the data that has been currently collected.

```bash
# How many events total
wc -l /opt/cowrie-logs/cowrie.json

# How many countries so far
cat /opt/cowrie-logs/cowrie_enriched.json | python3 -c "
import sys, json
from collections import Counter
countries = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('src_country') and e['src_country'] != 'Unknown':
            countries[e['src_country']] += 1
    except: pass
for country, count in countries.most_common(15):
    print(f'{count:>8} {country}')
"

# What credentials attackers are trying
cat /opt/cowrie-logs/cowrie.json | python3 -c "
import sys, json
from collections import Counter
passwords = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('eventid') == 'cowrie.login.failed':
            passwords[e.get('password','')] += 1
    except: pass
print('Top 20 passwords attempted:')
for pw, count in passwords.most_common(20):
    print(f'{count:>8} {pw}')
"

# What commands attackers ran after login
cat /opt/cowrie-logs/cowrie.json | python3 -c "
import sys, json
from collections import Counter
cmds = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('eventid') == 'cowrie.command.input':
            cmds[e.get('input','')] += 1
    except: pass
print('Top 20 commands run in fake shell:')
for cmd, count in cmds.most_common(20):
    print(f'{count:>8} {cmd}')
"

# Check nginx web attacks
wc -l /opt/cowrie-logs/nginx/access.log
tail -20 /opt/cowrie-logs/nginx/access.log
