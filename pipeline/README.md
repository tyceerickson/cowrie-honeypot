# Pipeline

Data processing pipeline for the Cowrie honeypot intelligence platform. These scripts handle the full data lifecycle from raw log collection through GeoIP enrichment to Wazuh SIEM export.

---

## Scripts

### `enrich_logs.py` — GeoIP Enrichment

Reads raw Cowrie JSON logs and adds geographic and ASN data to every event that contains a `src_ip` field. Runs hourly on Ubuntu Server via cron.

```bash
# UBUNTU SERVER
python3 /opt/cowrie-tools/pipeline/enrich_logs.py

# With custom paths
python3 enrich_logs.py \
  --input /opt/cowrie-logs/cowrie.json \
  --output /opt/cowrie-logs/cowrie_enriched.json
```

**Input:** `/opt/cowrie-logs/cowrie.json`  
**Output:** `/opt/cowrie-logs/cowrie_enriched.json`  
**Databases:** `/opt/geoip/GeoLite2-City.mmdb`, `/opt/geoip/GeoLite2-ASN.mmdb`  
**Cron:** `0 * * * *` (hourly)

Fields added to each event:

| Field | Example | Source |
|-------|---------|--------|
| `src_country` | `"Singapore"` | GeoLite2-City |
| `src_country_code` | `"SG"` | GeoLite2-City |
| `src_city` | `"Central"` | GeoLite2-City |
| `src_asn` | `"AS45102"` | GeoLite2-ASN |
| `src_org` | `"Alibaba (US) Technology Co."` | GeoLite2-ASN |

---

### `hassh_identify.py` — HASSH Tool Fingerprinting

Identifies SSH client tools from HASSH fingerprints using algorithm string pattern matching and a persistent local cache. No external database required, works on any unknown hash automatically.

```bash
# UBUNTU SERVER — show current cache
python3 /opt/cowrie-tools/pipeline/hassh_identify.py --show-cache

# Identify a specific hash
python3 hassh_identify.py <hassh> <hassh_algorithms>

# Clear and reseed cache
python3 hassh_identify.py --clear-cache
```

**Cache:** `/opt/geoip/hassh_cache.json` (grows automatically, 30+ entries seeded)

**Identification methods:**

1. **Cache lookup** — instant, checks previously identified hashes first
2. **Algorithm pattern matching** — analyzes the SSH key exchange algorithm string to identify the tool family. Works on hashes never seen before.

Pattern rules:
- `mlkem768nistp256` in kex → OpenSSH 9.9+
- `mlkem768x25519` in kex → OpenSSH 9.0-9.7
- `group1-sha1` + modern ciphers → Paramiko 2.x
- No curve25519, only CBC ciphers → Dropbear/IoT
- Starts with `ecdh-sha2-nistp256`, no curve25519 → libssh

**Day 1 capture results (May 2026):**

| HASSH | Sessions | Tool |
|-------|---------|------|
| `f555226df1963d1d3c09daf865abdc9a` | 825 | Paramiko 2.x |
| `03a80b21afa810682a776a7d42e5e6fb` | 122 | AsyncSSH |
| `16443846184eafde36765c9bab2f4397` | 21 | OpenSSH 9.x (post-quantum) |
| `af8223ac9914f509afdadfaf5f7ee94e` | 10 | OpenSSH 9.9+ |

---

### `export_to_wazuh.py` — Wazuh Export Pipeline

Transforms GeoIP-enriched Cowrie logs into Wazuh-ready format and generates all configuration files needed for Project 4 SIEM integration.

```bash
# UBUNTU SERVER
python3 /opt/cowrie-tools/pipeline/export_to_wazuh.py

# With custom paths
python3 export_to_wazuh.py \
  --input /opt/cowrie-logs/cowrie_enriched.json \
  --output-dir /opt/cowrie-logs/wazuh \
  --wazuh-manager 192.168.10.x
```

**Input:** `/opt/cowrie-logs/cowrie_enriched.json`  
**Output directory:** `/opt/cowrie-logs/wazuh/`

Output files:

| File | Purpose |
|------|---------|
| `wazuh-cowrie.json` | Normalized log — Wazuh agent monitors this file |
| `wazuh-agent-config.xml` | ossec.conf snippet — add to Wazuh agent |
| `wazuh-cowrie-rules.xml` | Custom rules — add to Wazuh manager |
| `export-summary.md` | Export statistics and next steps |

**Export results (24-hour capture):**
- 8,472 events exported, all GeoIP enriched
- 486 high-value events (Wazuh level ≥10)
- 236 SSH key implant attempts (level 12)
- Custom rules cover 11 distinct Cowrie event types

---

### `update_geoip.sh` — GeoIP Database Updater

Downloads fresh MaxMind GeoLite2 databases weekly. Requires a free MaxMind account.

```bash
# UBUNTU SERVER — runs automatically via cron
# Cron: 0 6 * * 1 (every Monday at 06:00 UTC)
/opt/geoip/update_db.sh
```

---

## Cron Schedule (Ubuntu Server)

| Schedule | Script | Purpose |
|----------|--------|---------|
| `*/15 * * * *` | rsync on VPS | Pull logs from VPS to Ubuntu Server |
| `0 * * * *` | `enrich_logs.py` | GeoIP enrichment |
| `0 6 * * 1` | `update_geoip.sh` | Weekly GeoIP database update |

---

## Dependencies

```bash
# UBUNTU SERVER
pip3 install geoip2 --break-system-packages

# GeoIP databases (free MaxMind account required)
# Download to /opt/geoip/
# GeoLite2-City.mmdb (63MB)
# GeoLite2-ASN.mmdb  (12MB)
```

---

## Data Flow

```
VPS cowrie.json (live)
        │
        │ rsync every 15 min (via WireGuard)
        ▼
/opt/cowrie-logs/cowrie.json
        │
        │ enrich_logs.py (hourly)
        ▼
/opt/cowrie-logs/cowrie_enriched.json
        │
        ├── analysis/analyze_sessions.py  → results/
        ├── analysis/explain_sessions.py  → results/session-explanations.md
        └── pipeline/export_to_wazuh.py  → /opt/cowrie-logs/wazuh/
                                               └── → Wazuh SIEM (Project 4)
```
