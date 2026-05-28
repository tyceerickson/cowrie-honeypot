# Wazuh Export Summary

> Generated: 2026-05-28 17:01 UTC
> Input: Full OpenSearch export — 11,611,908 events
> Output: `/opt/cowrie-logs/wazuh/wazuh-cowrie.json`
> Script: `pipeline/export_to_wazuh.py`

---

## Export Statistics

| Metric | Value |
|--------|-------|
| Total events exported | 11,611,908 |
| Events with GeoIP data | 11,611,908 |
| High-value events (level ≥10) | 575,337 |
| SSH key implant events | 149,348 |
| Malware download attempts | 165,580 |
| File uploads | 5,252 |
| Successful logins (level 10+) | 5,358 |

---

## Wazuh Alert Severity Distribution

| Severity | Level | Alerts |
|----------|-------|--------|
| CRITICAL | 12 | 14,377 |
| HIGH | 10 | 561,960 |
| MEDIUM-HIGH | 8 | 487,328 |
| MEDIUM | 6 | 809,585 |
| LOW | 3 | 9,266,451 |

---

## Event Type Breakdown

| Event Type | Count |
|-----------|-------|
| `cowrie.session.connect` | 2,622,641 |
| `cowrie.session.closed` | 2,623,702 |
| `cowrie.client.version` | 1,340,503 |
| `cowrie.client.kex` | 1,337,064 |
| `cowrie.login.failed` | 873,373 |
| `cowrie.command.input` | 501,689 |
| `cowrie.log.closed` | 490,629 |
| `cowrie.session.params` | 490,612 |
| `cowrie.login.success` | 461,930 |
| `cowrie.session.file_download` | 165,580 |
| `cowrie.command.failed` | 164,567 |
| `cowrie.telnet.option` | 7,864 |
| `cowrie.session.file_upload` | 5,252 |
| `cowrie.client.fingerprint` | 2,702 |
| `cowrie.direct-tcpip.request` | 2,597 |

---

## Wazuh Integration Files

| File | Purpose | Location |
|------|---------|----------|
| `wazuh-cowrie.json` | Normalized log — Wazuh agent monitors this | `/opt/cowrie-logs/wazuh/` |
| `wazuh-agent-config.xml` | ossec.conf snippet — add to Wazuh agent | `config/wazuh/` |
| `wazuh-cowrie-rules.xml` | Custom rules — deployed to Wazuh manager | `config/wazuh/` |

---

## Project 4 Integration Status

Wazuh SIEM is fully operational on Ubuntu Server (192.168.10.4) as part of Project 4.
All 11,611,908 events are indexed in OpenSearch and powering the AI-powered SOC dashboard.

| Step | Status |
|------|--------|
| Wazuh agent installed on Ubuntu Server | ✅ Complete |
| `wazuh-agent-config.xml` deployed | ✅ Complete |
| `wazuh-cowrie-rules.xml` deployed to manager | ✅ Complete |
| Events appearing in Wazuh dashboard | ✅ Complete — 11.6M events indexed |
| AI triage layer operational | ✅ Complete — Project 4 |
| Custom Wazuh rules firing alerts | ✅ Complete — 14,377 CRITICAL alerts |

See Project 4 repository: `wazuh-soc-pipeline` for the full SOC dashboard implementation.
