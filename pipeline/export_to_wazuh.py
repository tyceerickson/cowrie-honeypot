#!/usr/bin/env python3
"""
export_to_wazuh.py — Cowrie to Wazuh Export Pipeline
=====================================================
Transforms GeoIP-enriched Cowrie JSON logs into Wazuh-ready format and
generates the Wazuh agent configuration needed to ingest them.

Wazuh uses its native JSON decoder for Cowrie logs — no custom decoder
is required. This script:
  1. Normalizes Cowrie field names to Wazuh-compatible schema
  2. Adds rule-hint labels for automatic alert categorization
  3. Adds GeoIP fields in Wazuh's expected location.* format
  4. Writes wazuh-cowrie.json (the file Wazuh agent monitors)
  5. Generates ossec.conf snippet for Wazuh agent configuration
  6. Generates custom Wazuh rules file for Cowrie alert tuning

Usage:
    # Run on Ubuntu Server (192.168.10.4)
    python3 export_to_wazuh.py
    python3 export_to_wazuh.py --input /opt/cowrie-logs/cowrie_enriched.json
    python3 export_to_wazuh.py --output-dir /opt/cowrie-logs/wazuh/

Wazuh Integration:
    1. Run this script to generate wazuh-cowrie.json
    2. Install Wazuh agent on Ubuntu Server (Project 4)
    3. Add the generated ossec.conf snippet to agent config
    4. Add the generated rules file to Wazuh manager
    5. Restart agent: systemctl restart wazuh-agent

Output files:
    wazuh-cowrie.json        — Normalized log for Wazuh ingestion
    wazuh-agent-config.xml   — ossec.conf localfile snippet
    wazuh-cowrie-rules.xml   — Custom Wazuh rules for Cowrie alerts
    export-summary.md        — Summary of export statistics

References:
    https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
    https://github.com/wazuh/wazuh-ruleset/issues/601
"""

import json
import argparse
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

# ============================================================
# Configuration
# ============================================================
DEFAULT_INPUT      = "/opt/cowrie-logs/cowrie_enriched.json"
DEFAULT_OUTPUT_DIR = "/opt/cowrie-logs/wazuh"

# Wazuh rule ID ranges (custom rules start at 100000+)
RULE_ID_BASE = 100100

# Cowrie eventid → Wazuh rule mapping
EVENT_RULES = {
    "cowrie.session.connect":    (RULE_ID_BASE + 0,  3, "Honeypot SSH connection attempt"),
    "cowrie.login.failed":       (RULE_ID_BASE + 1,  6, "Honeypot SSH brute force attempt"),
    "cowrie.login.success":      (RULE_ID_BASE + 2, 10, "Honeypot SSH successful login — T1110"),
    "cowrie.command.input":      (RULE_ID_BASE + 3,  8, "Honeypot command execution — T1059"),
    "cowrie.session.closed":     (RULE_ID_BASE + 4,  3, "Honeypot SSH session closed"),
    "cowrie.client.version":     (RULE_ID_BASE + 5,  3, "Honeypot SSH client version"),
    "cowrie.client.kex":         (RULE_ID_BASE + 6,  3, "Honeypot SSH HASSH fingerprint"),
    "cowrie.direct-tcpip.data":  (RULE_ID_BASE + 7,  8, "Honeypot TCP tunnel attempt — T1572"),
    "cowrie.log.closed":         (RULE_ID_BASE + 8,  3, "Honeypot TTY log closed"),
    "cowrie.session.params":     (RULE_ID_BASE + 9,  3, "Honeypot session parameters"),
}

# High-value command patterns for rule escalation
HIGH_VALUE_COMMANDS = [
    ("authorized_keys", 12, "Honeypot SSH key implant attempt — T1098.004"),
    ("wget ",           10, "Honeypot malware download attempt — T1105"),
    ("curl ",           10, "Honeypot malware download attempt — T1105"),
    ("chpasswd",        12, "Honeypot password change attempt — T1098"),
    ("crontab",         10, "Honeypot persistence attempt — T1053"),
    ("chmod +x",        10, "Honeypot executable permission change — T1222"),
    ("rm -rf",          10, "Honeypot destructive command — T1070"),
    ("/etc/passwd",      8, "Honeypot credential file access — T1003"),
    ("cpuinfo",          7, "Honeypot cryptominer recon — T1082"),
    ("uname",            5, "Honeypot system info discovery — T1082"),
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export Cowrie logs to Wazuh-compatible format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 export_to_wazuh.py
  python3 export_to_wazuh.py --input /opt/cowrie-logs/cowrie_enriched.json
  python3 export_to_wazuh.py --output-dir /opt/cowrie-logs/wazuh/
        """
    )
    parser.add_argument("--input", default=DEFAULT_INPUT,
                        help=f"GeoIP-enriched Cowrie JSON (default: {DEFAULT_INPUT})")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--wazuh-manager", default="192.168.10.x",
                        help="Wazuh manager IP (for config generation)")
    return parser.parse_args()


def normalize_event(event):
    """
    Normalize a Cowrie event to Wazuh-compatible JSON format.

    Wazuh's JSON decoder extracts all fields automatically.
    We add:
    - location field (identifies log source)
    - rule hints (help Wazuh match custom rules)
    - GeoIP in location.* format (Wazuh standard)
    - MITRE ATT&CK labels where applicable
    """
    normalized = {}

    # ── Core fields (pass through unchanged) ──────────────────
    normalized["eventid"]   = event.get("eventid", "")
    normalized["timestamp"] = event.get("timestamp", "")
    normalized["session"]   = event.get("session", "")
    normalized["protocol"]  = event.get("protocol", "ssh")
    normalized["sensor"]    = event.get("sensor", "")
    normalized["message"]   = event.get("message", "")

    # ── Source IP and network fields ───────────────────────────
    if event.get("src_ip"):
        normalized["src_ip"]   = event["src_ip"]
        normalized["src_port"] = event.get("src_port", 0)

    # ── GeoIP in Wazuh location.* format ──────────────────────
    if event.get("src_country"):
        normalized["location"] = {
            "country_name": event.get("src_country", "Unknown"),
            "country_code": event.get("src_country_code", "XX"),
            "city_name":    event.get("src_city", "Unknown"),
            "asn":          event.get("src_asn", "Unknown"),
            "org":          event.get("src_org", "Unknown"),
        }

    # ── Credential fields ──────────────────────────────────────
    if event.get("username"):
        normalized["username"] = event["username"]
    if event.get("password"):
        normalized["password"] = event["password"]

    # ── Command fields with MITRE labeling ────────────────────
    if event.get("input"):
        cmd = event["input"]
        normalized["command"] = cmd

        # Check for high-value command patterns
        for pattern, level, description in HIGH_VALUE_COMMANDS:
            if pattern.lower() in cmd.lower():
                normalized["alert_level"]   = level
                normalized["alert_label"]   = description
                # Extract MITRE technique ID from description
                if "T1" in description:
                    technique = description.split("T1")[1].split(")")[0].split(" ")[0]
                    normalized["mitre_technique"] = f"T1{technique}"
                break

    # ── HASSH fingerprint ──────────────────────────────────────
    if event.get("hassh"):
        normalized["hassh"]           = event["hassh"]
        normalized["hasshAlgorithms"] = event.get("hasshAlgorithms", "")

    # ── SSH client version ─────────────────────────────────────
    if event.get("version"):
        normalized["ssh_client_version"] = event["version"]

    # ── Session duration ───────────────────────────────────────
    if event.get("duration"):
        normalized["duration"] = event["duration"]

    # ── Wazuh metadata ─────────────────────────────────────────
    normalized["honeypot"]        = "cowrie"
    normalized["honeypot_type"]   = "ssh_telnet"
    normalized["honeypot_sensor"] = "digitalocean-nyc1"

    # Add rule hint based on eventid
    eid = normalized["eventid"]
    if eid in EVENT_RULES:
        rule_id, level, desc = EVENT_RULES[eid]
        normalized["wazuh_rule_hint"] = rule_id
        normalized["wazuh_level"]     = level

    return normalized


def generate_agent_config(output_dir, wazuh_manager, wazuh_output_file):
    """Generate the ossec.conf snippet for the Wazuh agent."""
    config = f"""<!-- ============================================================
     Wazuh Agent Configuration for Cowrie Honeypot
     Add this block to: /var/ossec/etc/ossec.conf
     on Ubuntu Server (192.168.10.4) after Wazuh agent install

     Project 4 integration — cowrie-honeypot → wazuh-soc-pipeline
     ============================================================ -->

<ossec_config>

  <!-- Wazuh Manager Connection -->
  <client>
    <server>
      <address>{wazuh_manager}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu24</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- Cowrie SSH/Telnet Honeypot Logs (GeoIP-enriched) -->
  <!-- Primary ingestion source — normalized by export_to_wazuh.py -->
  <localfile>
    <log_format>json</log_format>
    <location>{wazuh_output_file}</location>
    <label key="honeypot">cowrie</label>
    <label key="sensor">digitalocean-nyc1</label>
  </localfile>

  <!-- Raw Cowrie logs (backup — direct from rsync) -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/cowrie-logs/cowrie.json</location>
    <label key="honeypot">cowrie-raw</label>
  </localfile>

  <!-- nginx Web Honeypot Logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/opt/cowrie-logs/nginx/access.log</location>
    <label key="honeypot">nginx-web</label>
  </localfile>

  <!-- Dionaea Malware Capture Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/cowrie-logs/dionaea/dionaea.log</location>
    <label key="honeypot">dionaea</label>
  </localfile>

</ossec_config>
"""
    config_path = Path(output_dir) / "wazuh-agent-config.xml"
    with open(config_path, "w") as f:
        f.write(config)
    return config_path


def generate_wazuh_rules(output_dir):
    """Generate custom Wazuh rules for Cowrie alerts."""
    rules = f"""<!-- ============================================================
     Custom Wazuh Rules for Cowrie Honeypot
     File: /var/ossec/etc/rules/cowrie-rules.xml
     On Wazuh Manager — copy this file there during Project 4

     Rule IDs: {RULE_ID_BASE}-{RULE_ID_BASE + 20}
     ============================================================ -->

<group name="cowrie,honeypot,">

  <!-- ── Base rule — all Cowrie events ──────────────────── -->
  <rule id="{RULE_ID_BASE}" level="3">
    <decoded_as>json</decoded_as>
    <field name="honeypot">cowrie</field>
    <description>Cowrie honeypot event</description>
    <group>honeypot,</group>
  </rule>

  <!-- ── SSH connection to honeypot ────────────────────── -->
  <rule id="{RULE_ID_BASE + 1}" level="3">
    <if_sid>{RULE_ID_BASE}</if_sid>
    <field name="eventid">cowrie.session.connect</field>
    <description>Honeypot: New SSH connection from $(src_ip)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>honeypot,connection,</group>
  </rule>

  <!-- ── SSH brute force ───────────────────────────────── -->
  <rule id="{RULE_ID_BASE + 2}" level="6">
    <if_sid>{RULE_ID_BASE}</if_sid>
    <field name="eventid">cowrie.login.failed</field>
    <description>Honeypot: Failed SSH login attempt [$(username)/$(password)] from $(src_ip)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>honeypot,authentication_failed,brute_force,</group>
  </rule>

  <!-- ── Successful login ──────────────────────────────── -->
  <rule id="{RULE_ID_BASE + 3}" level="10">
    <if_sid>{RULE_ID_BASE}</if_sid>
    <field name="eventid">cowrie.login.success</field>
    <description>Honeypot: Successful SSH login [$(username)/$(password)] from $(src_ip)</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>honeypot,authentication_success,</group>
  </rule>

  <!-- ── Command execution ─────────────────────────────── -->
  <rule id="{RULE_ID_BASE + 4}" level="8">
    <if_sid>{RULE_ID_BASE}</if_sid>
    <field name="eventid">cowrie.command.input</field>
    <description>Honeypot: Command executed: $(command)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>honeypot,command,</group>
  </rule>

  <!-- ── SSH key implant ───────────────────────────────── -->
  <rule id="{RULE_ID_BASE + 5}" level="12">
    <if_sid>{RULE_ID_BASE + 4}</if_sid>
    <field name="command">authorized_keys</field>
    <description>Honeypot: SSH key backdoor implant attempt from $(src_ip)</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
    <group>honeypot,backdoor,persistence,</group>
  </rule>

  <!-- ── Malware download attempt ─────────────────────── -->
  <rule id="{RULE_ID_BASE + 6}" level="10">
    <if_sid>{RULE_ID_BASE + 4}</if_sid>
    <field name="command">\.wget |\.curl |\.tftp </field>
    <description>Honeypot: Malware download attempt from $(src_ip)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
    <group>honeypot,malware,download,</group>
  </rule>

  <!-- ── Password change attempt ──────────────────────── -->
  <rule id="{RULE_ID_BASE + 7}" level="12">
    <if_sid>{RULE_ID_BASE + 4}</if_sid>
    <field name="command">chpasswd|passwd</field>
    <description>Honeypot: Password change attempt from $(src_ip)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>honeypot,credential_access,</group>
  </rule>

  <!-- ── Cryptominer recon ─────────────────────────────── -->
  <rule id="{RULE_ID_BASE + 8}" level="8">
    <if_sid>{RULE_ID_BASE + 4}</if_sid>
    <field name="command">cpuinfo|nproc|lscpu|free -m</field>
    <description>Honeypot: Cryptominer reconnaissance from $(src_ip)</description>
    <mitre>
      <id>T1082</id>
    </mitre>
    <group>honeypot,cryptominer,recon,</group>
  </rule>

  <!-- ── HASSH fingerprint logged ─────────────────────── -->
  <rule id="{RULE_ID_BASE + 9}" level="3">
    <if_sid>{RULE_ID_BASE}</if_sid>
    <field name="eventid">cowrie.client.kex</field>
    <description>Honeypot: SSH client fingerprinted HASSH=$(hassh) from $(src_ip)</description>
    <group>honeypot,fingerprint,</group>
  </rule>

  <!-- ── Brute force frequency alert ──────────────────── -->
  <rule id="{RULE_ID_BASE + 10}" level="10" frequency="10" timeframe="60">
    <if_matched_sid>{RULE_ID_BASE + 2}</if_matched_sid>
    <same_field>src_ip</same_field>
    <description>Honeypot: SSH brute force attack — 10+ attempts from $(src_ip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>honeypot,brute_force,</group>
  </rule>

</group>
"""
    rules_path = Path(output_dir) / "wazuh-cowrie-rules.xml"
    with open(rules_path, "w") as f:
        f.write(rules)
    return rules_path


def write_summary(stats, output_dir, output_file):
    """Write export summary markdown."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary_path = Path(output_dir) / "export-summary.md"

    lines = [
        "# Wazuh Export Summary",
        f"\n> Generated: {now}",
        f"> Input: GeoIP-enriched Cowrie JSON",
        f"> Output: `{output_file}`\n",
        "## Export Statistics\n",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total events exported | {stats['total']:,} |",
        f"| Events with GeoIP data | {stats['with_geo']:,} |",
        f"| High-value events (level ≥10) | {stats['high_value']:,} |",
        f"| SSH key implant events | {stats['implant']:,} |",
        f"| Malware download attempts | {stats['malware']:,} |",
        "\n## Event Type Breakdown\n",
        "| Event Type | Count |",
        "|-----------|-------|",
    ]

    for eid, count in sorted(stats["event_types"].items(),
                              key=lambda x: x[1], reverse=True):
        lines.append(f"| `{eid}` | {count:,} |")

    lines += [
        "\n## Wazuh Integration Files\n",
        "| File | Purpose |",
        "|------|---------|",
        "| `wazuh-cowrie.json` | Normalized log file — Wazuh agent monitors this |",
        "| `wazuh-agent-config.xml` | ossec.conf snippet — add to Wazuh agent config |",
        "| `wazuh-cowrie-rules.xml` | Custom rules — add to Wazuh manager |",
        "\n## Next Steps (Project 4)\n",
        "1. Install Wazuh agent on Ubuntu Server (192.168.10.4)",
        "2. Copy `wazuh-agent-config.xml` content into `/var/ossec/etc/ossec.conf`",
        "3. Copy `wazuh-cowrie-rules.xml` to `/var/ossec/etc/rules/` on Wazuh manager",
        "4. Restart agent: `systemctl restart wazuh-agent`",
        "5. Verify logs appear in Wazuh dashboard under honeypot group",
        "6. Import provided rules for automatic alerting",
    ]

    with open(summary_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return summary_path


def main():
    args = parse_args()

    print("[+] export_to_wazuh.py — Cowrie to Wazuh Export")
    print(f"[+] Input:      {args.input}")
    print(f"[+] Output dir: {args.output_dir}")
    print()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "wazuh-cowrie.json"

    # Load and transform events
    print(f"[+] Loading events from {args.input}")
    if not Path(args.input).exists():
        print(f"[-] Input file not found: {args.input}")
        sys.exit(1)

    stats = {
        "total":       0,
        "with_geo":    0,
        "high_value":  0,
        "implant":     0,
        "malware":     0,
        "event_types": Counter(),
    }

    print(f"[+] Normalizing events for Wazuh ingestion...")

    with open(args.input, 'r', encoding='utf-8') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:

        for line in infile:
            line = line.strip()
            if not line:
                continue
            try:
                event      = json.loads(line)
                normalized = normalize_event(event)

                outfile.write(json.dumps(normalized) + "\n")

                # Update stats
                stats["total"] += 1
                stats["event_types"][normalized.get("eventid", "unknown")] += 1

                if normalized.get("location"):
                    stats["with_geo"] += 1
                if normalized.get("wazuh_level", 0) >= 10:
                    stats["high_value"] += 1
                if "authorized_keys" in normalized.get("command", ""):
                    stats["implant"] += 1
                if any(x in normalized.get("command", "")
                       for x in ["wget ", "curl "]):
                    stats["malware"] += 1

            except json.JSONDecodeError:
                continue

    print(f"[+] Exported {stats['total']:,} events to {output_file}")
    print(f"    With GeoIP:    {stats['with_geo']:,}")
    print(f"    High value:    {stats['high_value']:,} (level ≥10)")
    print(f"    Key implants:  {stats['implant']:,}")
    print(f"    Malware DLs:   {stats['malware']:,}")

    # Generate config files
    print(f"\n[+] Generating Wazuh configuration files...")

    config_path = generate_agent_config(
        output_dir, args.wazuh_manager, str(output_file)
    )
    print(f"    Agent config:  {config_path}")

    rules_path = generate_wazuh_rules(output_dir)
    print(f"    Custom rules:  {rules_path}")

    summary_path = write_summary(stats, output_dir, str(output_file))
    print(f"    Summary:       {summary_path}")

    # Print final structure
    print(f"\n[+] Output directory contents:")
    for f in sorted(output_dir.iterdir()):
        size = f.stat().st_size
        print(f"    {f.name:<35} {size:>10,} bytes")

    print(f"\n[+] Wazuh integration ready.")
    print(f"    Next: Install Wazuh agent on Ubuntu Server (Project 4)")
    print(f"    Config snippet: {config_path}")
    print(f"    Custom rules:   {rules_path}")
    print("[+] Done.")


if __name__ == "__main__":
    main()
