# Wazuh Export Summary

> Generated: 2026-05-22 16:27 UTC
> Input: GeoIP-enriched Cowrie JSON
> Output: `/opt/cowrie-logs/wazuh/wazuh-cowrie.json`

## Export Statistics

| Metric | Value |
|--------|-------|
| Total events exported | 8,472 |
| Events with GeoIP data | 8,472 |
| High-value events (level ≥10) | 486 |
| SSH key implant events | 236 |
| Malware download attempts | 0 |

## Event Type Breakdown

| Event Type | Count |
|-----------|-------|
| `cowrie.session.connect` | 1,640 |
| `cowrie.session.closed` | 1,640 |
| `cowrie.client.version` | 1,067 |
| `cowrie.client.kex` | 1,060 |
| `cowrie.login.failed` | 566 |
| `cowrie.command.input` | 510 |
| `cowrie.session.params` | 505 |
| `cowrie.log.closed` | 505 |
| `cowrie.login.success` | 486 |
| `cowrie.session.file_download` | 237 |
| `cowrie.command.failed` | 236 |
| `cowrie.telnet.option` | 14 |
| `cowrie.session.file_upload` | 6 |

## Wazuh Integration Files

| File | Purpose |
|------|---------|
| `wazuh-cowrie.json` | Normalized log file — Wazuh agent monitors this |
| `wazuh-agent-config.xml` | ossec.conf snippet — add to Wazuh agent config |
| `wazuh-cowrie-rules.xml` | Custom rules — add to Wazuh manager |

## Next Steps (Project 4)

1. Install Wazuh agent on Ubuntu Server (192.168.10.4)
2. Copy `wazuh-agent-config.xml` content into `/var/ossec/etc/ossec.conf`
3. Copy `wazuh-cowrie-rules.xml` to `/var/ossec/etc/rules/` on Wazuh manager
4. Restart agent: `systemctl restart wazuh-agent`
5. Verify logs appear in Wazuh dashboard under honeypot group
6. Import provided rules for automatic alerting
