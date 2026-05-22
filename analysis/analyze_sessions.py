#!/usr/bin/env python3
"""
analyze_sessions.py — Project 3: Cowrie Honeypot Analysis
==========================================================
Reads GeoIP-enriched Cowrie JSON logs and produces a full attack intelligence
report including credential analysis, geographic breakdown, HASSH tool
fingerprinting, command analysis, session statistics, and attack velocity.

Follows the same code patterns as Project 2 (ai-traffic-classifier):
- argparse for CLI flexibility
- [+] progress output with [!] warnings and [-] errors
- config-driven paths
- explicit error handling
- outputs to results/ directory

Usage:
    python3 analyze_sessions.py
    python3 analyze_sessions.py --input /opt/cowrie-logs/cowrie_enriched.json
    python3 analyze_sessions.py --input /opt/cowrie-logs/cowrie_enriched.json --output-dir ./results
    python3 analyze_sessions.py --no-charts  # skip matplotlib if not installed

Dependencies:
    pip3 install matplotlib pandas --break-system-packages
    (matplotlib optional — use --no-charts if unavailable)

Output files (written to --output-dir, default: ../results/):
    attack-analysis.md      — Full markdown analysis report
    top-credentials.csv     — Top username/password pairs
    attacker-countries.csv  — Country breakdown with ASN data
    charts/attacks-by-country.png
    charts/attacks-by-hour.png
    charts/top-passwords.png
    charts/top-usernames.png
"""

import json
import argparse
import sys
import os
import csv
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ============================================================
# Configuration
# ============================================================
# Import HASSH identifier — uses pattern matching + persistent cache
# Cache: /opt/geoip/hassh_cache.json (grows automatically)
import importlib.util as _ilu, os as _os
_spec = _ilu.spec_from_file_location(
    'hassh_identify',
    '/opt/cowrie-tools/pipeline/hassh_identify.py'
)
_hassh_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_hassh_mod)
_HASSH_CACHE = _hassh_mod.load_cache()

def _lookup_hassh(hassh, algs=''):
    return _hassh_mod.identify_hassh(hassh, algs, _HASSH_CACHE)
DEFAULT_INPUT      = "/opt/cowrie-logs/cowrie_enriched.json"
DEFAULT_OUTPUT_DIR = str(Path(__file__).parent.parent / "results")

# Known HASSH fingerprints for tool identification
# Source: https://github.com/salesforce/hassh
KNOWN_HASSH = {
    # ── Identified from live capture data (May 2026) ──────────
    # Dominant scanner — 825 sessions
    "f555226df1963d1d3c09daf865abdc9a": "Paramiko 2.x (Python SSH library)",
    # Second most common — 122 sessions  
    "03a80b21afa810682a776a7d42e5e6fb": "AsyncSSH (Python async SSH framework)",
    # Post-quantum OpenSSH variants
    "16443846184eafde36765c9bab2f4397": "OpenSSH 9.0-9.7 (post-quantum mlkem support)",
    "af8223ac9914f509afdadfaf5f7ee94e": "OpenSSH 9.9+ (latest, mlkem768nistp256+sntrup761)",
    # Standard modern OpenSSH 8.x variants
    "671ac49b8bd65b9e8ff02a3e690f0fd3": "OpenSSH 8.x (standard modern client)",
    "e54ef3ec27fe1fea7ab64d3fa05359fd": "OpenSSH 8.x variant",
    "19532158b559096b89b1a5f7d17175b2": "OpenSSH 8.x variant",
    "5f904648ee8964bef0e8834012e26003": "OpenSSH 8.x variant",
    "9052c4ab4164c78256e71143dcfc7eac": "OpenSSH 8.x variant",
    "5bd26477da5440a6187bd3f1b39a429c": "OpenSSH 8.x variant",
    "4e066189c3bbeec38c99b1855113733a": "OpenSSH 8.x variant",
    # Older OpenSSH (libssh.org suffix style = pre-8.0)
    "bc9e7273cde22b1209d6673b5fd10bd5": "OpenSSH 7.x (older client)",
    "2aec6b44b06bec95d73f66b5d30cb69a": "OpenSSH 7.x (older client)",
    "7216c7c473918b4f83d1139b3c70dbf9": "OpenSSH 7.x (older client)",
    # Specialized/legacy tools
    "0a07365cc01fa9fc82608ba4019af499": "Go SSH scanner (automated internet scanner)",
    "f45fb203c31069bb280067b71ed92ccb": "libssh / custom tool (no curve25519)",
    "b21d7cdcc8133dc2b430d1a039fece20": "Legacy SSH library (pre-2015, no elliptic curve)",
    "dde267e50f82fcc16a7e1e7b59b8af71": "Ancient SSH client (pre-2013, DH-only, old botnet)",
    "a20aced7c9824fd804f59e68dd801ad3": "Dropbear SSH / IoT device (compromised router/camera)",
    # Common known fingerprints (not yet observed but likely)
    "eeca2460550b9ded084ecf2f70a75356": "OpenSSH standard client",
    "a7a87fbe86774c2e40cc4a7ea2ab1b3c": "PuTTY SSH client",
    "06046964c022c6407d15a27b12a6a4fb": "Hydra SSH brute force tool",
    "92674c807a75b28f1e6de964d02f4ce7": "Mirai botnet variant",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze Cowrie honeypot session data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyze_sessions.py
  python3 analyze_sessions.py --input /opt/cowrie-logs/cowrie_enriched.json
  python3 analyze_sessions.py --no-charts --top 50
        """
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help=f"Path to GeoIP-enriched Cowrie JSON log (default: {DEFAULT_INPUT})"
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to write results (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--no-charts",
        action="store_true",
        help="Skip chart generation (use if matplotlib not installed)"
    )
    parser.add_argument(
        "--top",
        type=int,
        default=25,
        help="Number of top entries to include in tables (default: 25)"
    )
    return parser.parse_args()


def load_events(input_path):
    """Load all events from enriched Cowrie JSON log."""
    print(f"[+] Loading events from {input_path}")

    if not Path(input_path).exists():
        print(f"[-] Input file not found: {input_path}")
        sys.exit(1)

    events = []
    skipped = 0

    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1

    print(f"[+] Loaded {len(events):,} events ({skipped} skipped)")
    return events


def analyze_events(events, top_n):
    """Extract all statistics from event list."""
    print(f"[+] Analyzing {len(events):,} events...")

    # Counters
    event_types        = Counter()
    countries          = Counter()
    country_codes      = Counter()
    asns               = Counter()
    orgs               = Counter()
    src_ips            = Counter()
    usernames          = Counter()
    passwords          = Counter()
    credential_pairs   = Counter()
    commands           = Counter()
    hassh_values       = Counter()
    hassh_alg_map      = {}
    client_versions    = Counter()
    protocols          = Counter()
    session_durations  = []

    # Session tracking
    sessions           = defaultdict(dict)
    successful_sessions = set()
    hourly_counts      = defaultdict(int)
    daily_counts       = defaultdict(int)

    for event in events:
        eid       = event.get("eventid", "")
        src_ip    = event.get("src_ip", "")
        session   = event.get("session", "")
        timestamp = event.get("timestamp", "")
        protocol  = event.get("protocol", "ssh")

        event_types[eid] += 1
        protocols[protocol] += 1

        # GeoIP fields
        country  = event.get("src_country", "Unknown")
        cc       = event.get("src_country_code", "XX")
        asn      = event.get("src_asn", "Unknown")
        org      = event.get("src_org", "Unknown")

        if src_ip:
            src_ips[src_ip] += 1
            if country and country != "Unknown":
                countries[country] += 1
                country_codes[cc] += 1
            if asn and asn != "Unknown":
                asns[asn] += 1
            if org and org != "Unknown":
                orgs[org] += 1

        # Parse timestamp for time-based analysis
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                day_key  = dt.strftime("%Y-%m-%d")
                hourly_counts[hour_key] += 1
                daily_counts[day_key]   += 1
            except (ValueError, AttributeError):
                pass

        # Event-specific processing
        if eid == "cowrie.login.failed":
            username = event.get("username", "")
            password = event.get("password", "")
            if username:
                usernames[username] += 1
            if password:
                passwords[password] += 1
            if username and password:
                credential_pairs[f"{username}:{password}"] += 1

        elif eid == "cowrie.login.success":
            username = event.get("username", "")
            password = event.get("password", "")
            if username:
                usernames[username] += 1
            if password:
                passwords[password] += 1
            if username and password:
                credential_pairs[f"{username}:{password}"] += 1
            successful_sessions.add(session)

        elif eid == "cowrie.command.input":
            cmd = event.get("input", "").strip()
            if cmd:
                commands[cmd] += 1

        elif eid == "cowrie.client.kex":
            hassh = event.get("hassh", "")
            algs  = event.get("hasshAlgorithms", "")
            if hassh:
                hassh_values[hassh] += 1
                if hassh not in hassh_alg_map:
                    hassh_alg_map[hassh] = algs

        elif eid == "cowrie.client.version":
            version = event.get("version", "")
            if version:
                client_versions[version] += 1

        elif eid == "cowrie.session.closed":
            try:
                duration = float(event.get("duration", 0))
                session_durations.append(duration)
            except (ValueError, TypeError):
                pass

        # Track session metadata
        if session and src_ip:
            sessions[session]["src_ip"]      = src_ip
            sessions[session]["country"]     = country
            sessions[session]["asn"]         = asn
            if eid == "cowrie.session.connect":
                sessions[session]["start"] = timestamp

    print(f"[+] Analysis complete:")
    print(f"    Unique source IPs:       {len(src_ips):,}")
    print(f"    Unique sessions:         {len(sessions):,}")
    print(f"    Successful logins:       {len(successful_sessions):,}")
    print(f"    Countries identified:    {len(countries):,}")
    print(f"    Unique HASSH values:     {len(hassh_values):,}")
    print(f"    Unique commands run:     {len(commands):,}")
    print(f"    Credential pairs tried:  {len(credential_pairs):,}")

    return {
        "total_events":         len(events),
        "event_types":          event_types,
        "countries":            countries,
        "country_codes":        country_codes,
        "asns":                 asns,
        "orgs":                 orgs,
        "src_ips":              src_ips,
        "usernames":            usernames,
        "passwords":            passwords,
        "credential_pairs":     credential_pairs,
        "commands":             commands,
        "hassh_values":         hassh_values,
        "hassh_alg_map":        hassh_alg_map,
        "client_versions":      client_versions,
        "protocols":            protocols,
        "session_durations":    session_durations,
        "sessions":             sessions,
        "successful_sessions":  successful_sessions,
        "hourly_counts":        hourly_counts,
        "daily_counts":         daily_counts,
    }


def generate_charts(stats, output_dir, top_n):
    """Generate analysis charts using matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
    except ImportError:
        print("[!] matplotlib not installed — skipping charts")
        print("    Install with: pip3 install matplotlib --break-system-packages")
        return

    charts_dir = Path(output_dir) / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update({
        "figure.facecolor": "white",
        "axes.facecolor":   "white",
        "axes.grid":        True,
        "grid.alpha":       0.3,
        "font.size":        10,
    })

    # ── Chart 1: Top Attacker Countries ──────────────────────
    print("[+] Generating chart: attacks-by-country.png")
    top_countries = stats["countries"].most_common(15)
    if top_countries:
        labels, values = zip(*top_countries)
        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(list(reversed(labels)), list(reversed(values)),
                       color="#E24B4A", edgecolor="white", linewidth=0.5)
        ax.set_xlabel("Number of Events")
        ax.set_title(f"Top 15 Attacker Countries — {stats['total_events']:,} Total Events",
                     fontsize=13, fontweight="bold")
        for bar, val in zip(bars, list(reversed(values))):
            ax.text(val + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{val:,}", va="center", fontsize=9)
        plt.tight_layout()
        plt.savefig(charts_dir / "attacks-by-country.png", dpi=150)
        plt.close()

    # ── Chart 2: Attack Volume by Hour ───────────────────────
    print("[+] Generating chart: attacks-by-hour.png")
    if stats["hourly_counts"]:
        hours  = sorted(stats["hourly_counts"].keys())
        counts = [stats["hourly_counts"][h] for h in hours]
        fig, ax = plt.subplots(figsize=(14, 5))
        ax.plot(range(len(hours)), counts, color="#1D9E75", linewidth=1.5)
        ax.fill_between(range(len(hours)), counts, alpha=0.2, color="#1D9E75")
        ax.set_xlabel("Time (UTC)")
        ax.set_ylabel("Events per Hour")
        ax.set_title("Attack Volume Over Time", fontsize=13, fontweight="bold")
        tick_interval = max(1, len(hours) // 12)
        ax.set_xticks(range(0, len(hours), tick_interval))
        ax.set_xticklabels(
            [hours[i][:13] for i in range(0, len(hours), tick_interval)],
            rotation=45, ha="right", fontsize=8
        )
        plt.tight_layout()
        plt.savefig(charts_dir / "attacks-by-hour.png", dpi=150)
        plt.close()

    # ── Chart 3: Top Passwords ───────────────────────────────
    print("[+] Generating chart: top-passwords.png")
    top_passwords = stats["passwords"].most_common(20)
    if top_passwords:
        labels, values = zip(*top_passwords)
        # Truncate long passwords for display
        display_labels = [p[:30] + "..." if len(p) > 30 else p for p in labels]
        fig, ax = plt.subplots(figsize=(12, 7))
        bars = ax.barh(list(reversed(display_labels)), list(reversed(values)),
                       color="#185FA5", edgecolor="white", linewidth=0.5)
        ax.set_xlabel("Attempts")
        ax.set_title("Top 20 Attempted Passwords", fontsize=13, fontweight="bold")
        for bar, val in zip(bars, list(reversed(values))):
            ax.text(val + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{val:,}", va="center", fontsize=9)
        plt.tight_layout()
        plt.savefig(charts_dir / "top-passwords.png", dpi=150)
        plt.close()

    # ── Chart 4: Top Usernames ───────────────────────────────
    print("[+] Generating chart: top-usernames.png")
    top_usernames = stats["usernames"].most_common(20)
    if top_usernames:
        labels, values = zip(*top_usernames)
        display_labels = [u[:30] + "..." if len(u) > 30 else u for u in labels]
        fig, ax = plt.subplots(figsize=(12, 7))
        ax.barh(list(reversed(display_labels)), list(reversed(values)),
                color="#BA7517", edgecolor="white", linewidth=0.5)
        ax.set_xlabel("Attempts")
        ax.set_title("Top 20 Attempted Usernames", fontsize=13, fontweight="bold")
        plt.tight_layout()
        plt.savefig(charts_dir / "top-usernames.png", dpi=150)
        plt.close()

    print(f"[+] Charts saved to {charts_dir}/")


def write_csv_files(stats, output_dir, top_n):
    """Write CSV data files."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── top-credentials.csv ──────────────────────────────────
    print("[+] Writing top-credentials.csv")
    cred_path = output_dir / "top-credentials.csv"
    with open(cred_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["rank", "username", "password", "attempts", "pct_of_total"])
        total_creds = sum(stats["credential_pairs"].values())
        for rank, (pair, count) in enumerate(
            stats["credential_pairs"].most_common(top_n), 1
        ):
            username, password = pair.split(":", 1) if ":" in pair else (pair, "")
            pct = (count / total_creds * 100) if total_creds > 0 else 0
            writer.writerow([rank, username, password, count, f"{pct:.2f}%"])
    print(f"    Wrote {min(top_n, len(stats['credential_pairs']))} credential pairs")

    # ── attacker-countries.csv ───────────────────────────────
    print("[+] Writing attacker-countries.csv")
    country_path = output_dir / "attacker-countries.csv"
    with open(country_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["rank", "country", "country_code", "events", "pct_of_total"])
        total_country_events = sum(stats["countries"].values())
        for rank, (country, count) in enumerate(
            stats["countries"].most_common(top_n), 1
        ):
            cc  = stats["country_codes"].get(country, "XX")
            # Find country code by matching country name
            for code, c_count in stats["country_codes"].items():
                pass  # country_codes is keyed by code not name
            pct = (count / total_country_events * 100) if total_country_events > 0 else 0
            writer.writerow([rank, country, "", count, f"{pct:.2f}%"])
    print(f"    Wrote {min(top_n, len(stats['countries']))} countries")


def write_markdown_report(stats, output_dir, top_n):
    """Write the full markdown analysis report."""
    print("[+] Writing attack-analysis.md")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "attack-analysis.md"

    # Compute summary statistics
    total_events      = stats["total_events"]
    unique_ips        = len(stats["src_ips"])
    unique_countries  = len(stats["countries"])
    total_logins_fail = stats["event_types"].get("cowrie.login.failed", 0)
    total_logins_succ = stats["event_types"].get("cowrie.login.success", 0)
    total_commands    = stats["event_types"].get("cowrie.command.input", 0)
    total_sessions    = stats["event_types"].get("cowrie.session.connect", 0)
    total_cred_pairs  = sum(stats["credential_pairs"].values())

    durations = stats["session_durations"]
    avg_duration = sum(durations) / len(durations) if durations else 0
    max_duration = max(durations) if durations else 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Attack Analysis Report — Cowrie Honeypot")
    lines.append(f"\n> Generated: {now}  ")
    lines.append(f"> Input: GeoIP-enriched Cowrie session data  ")
    lines.append(f"> Script: `analysis/analyze_sessions.py`\n")

    # ── Summary ──────────────────────────────────────────────
    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total events captured | {total_events:,} |")
    lines.append(f"| Unique source IPs | {unique_ips:,} |")
    lines.append(f"| Countries represented | {unique_countries} |")
    lines.append(f"| Total sessions | {total_sessions:,} |")
    lines.append(f"| Successful logins | {len(stats['successful_sessions']):,} |")
    lines.append(f"| Failed login attempts | {total_logins_fail:,} |")
    lines.append(f"| Commands executed | {total_commands:,} |")
    lines.append(f"| Unique credential pairs | {len(stats['credential_pairs']):,} |")
    lines.append(f"| Avg session duration | {avg_duration:.1f}s |")
    lines.append(f"| Max session duration | {max_duration:.1f}s |")
    lines.append(f"| Unique HASSH fingerprints | {len(stats['hassh_values'])} |")

    # ── Event Type Breakdown ──────────────────────────────────
    lines.append("\n## Event Type Breakdown\n")
    lines.append("| Event Type | Count |")
    lines.append("|-----------|-------|")
    for eid, count in sorted(stats["event_types"].items(),
                              key=lambda x: x[1], reverse=True):
        lines.append(f"| `{eid}` | {count:,} |")

    # ── Geographic Analysis ───────────────────────────────────
    lines.append("\n## Geographic Analysis\n")
    lines.append("![Attacks by Country](charts/attacks-by-country.png)\n")
    lines.append(f"### Top {min(top_n, len(stats['countries']))} Attacker Countries\n")
    lines.append("| Rank | Country | Events | % of Geo-Tagged |")
    lines.append("|------|---------|--------|----------------|")
    total_geo = sum(stats["countries"].values())
    for rank, (country, count) in enumerate(
        stats["countries"].most_common(top_n), 1
    ):
        pct = count / total_geo * 100 if total_geo > 0 else 0
        lines.append(f"| {rank} | {country} | {count:,} | {pct:.1f}% |")

    lines.append(f"\n### Top {min(top_n, len(stats['asns']))} Attacker ASNs\n")
    lines.append("| Rank | ASN | Organization | Events |")
    lines.append("|------|-----|-------------|--------|")
    for rank, (asn, count) in enumerate(stats["asns"].most_common(top_n), 1):
        org = ""
        # Find org for this ASN from orgs counter (best effort)
        lines.append(f"| {rank} | `{asn}` | | {count:,} |")

    # ── Credential Analysis ───────────────────────────────────
    lines.append("\n## Credential Analysis\n")
    lines.append("![Top Passwords](charts/top-passwords.png)\n")
    lines.append("![Top Usernames](charts/top-usernames.png)\n")

    lines.append(f"### Top {min(top_n, len(stats['usernames']))} Attempted Usernames\n")
    lines.append("| Rank | Username | Attempts |")
    lines.append("|------|----------|---------|")
    for rank, (username, count) in enumerate(
        stats["usernames"].most_common(top_n), 1
    ):
        lines.append(f"| {rank} | `{username}` | {count:,} |")

    lines.append(f"\n### Top {min(top_n, len(stats['passwords']))} Attempted Passwords\n")
    lines.append("| Rank | Password | Attempts |")
    lines.append("|------|----------|---------|")
    for rank, (password, count) in enumerate(
        stats["passwords"].most_common(top_n), 1
    ):
        # Truncate very long passwords
        display_pw = password[:60] + "..." if len(password) > 60 else password
        lines.append(f"| {rank} | `{display_pw}` | {count:,} |")

    lines.append(f"\n### Top {min(top_n, len(stats['credential_pairs']))} Credential Pairs\n")
    lines.append("| Rank | Username | Password | Attempts |")
    lines.append("|------|----------|----------|---------|")
    for rank, (pair, count) in enumerate(
        stats["credential_pairs"].most_common(top_n), 1
    ):
        username, password = pair.split(":", 1) if ":" in pair else (pair, "")
        display_pw = password[:40] + "..." if len(password) > 40 else password
        lines.append(f"| {rank} | `{username}` | `{display_pw}` | {count:,} |")

    # ── HASSH Tool Fingerprinting ─────────────────────────────
    lines.append("\n## HASSH Tool Fingerprinting\n")
    lines.append("HASSH (SSH fingerprint) identifies the tool used by each attacker.\n")
    lines.append("| Rank | HASSH | Identified Tool | Sessions |")
    lines.append("|------|-------|----------------|---------|")
    for rank, (hassh, count) in enumerate(
        stats["hassh_values"].most_common(top_n), 1
    ):
        tool = _lookup_hassh(hassh, stats.get("hassh_alg_map", {}).get(hassh, ""))
        lines.append(f"| {rank} | `{hassh}` | {tool} | {count:,} |")

    # ── SSH Client Versions ───────────────────────────────────
    if stats["client_versions"]:
        lines.append(f"\n### SSH Client Version Strings\n")
        lines.append("| Client Version | Sessions |")
        lines.append("|---------------|---------|")
        for version, count in stats["client_versions"].most_common(15):
            lines.append(f"| `{version}` | {count:,} |")

    # ── Command Analysis ──────────────────────────────────────
    lines.append("\n## Command Analysis (Post-Login Behavior)\n")
    lines.append("Commands typed by attackers after gaining shell access.\n")
    lines.append(f"### Top {min(top_n, len(stats['commands']))} Commands Executed\n")
    lines.append("| Rank | Command | Executions | MITRE Technique |")
    lines.append("|------|---------|-----------|----------------|")

    # Map commands to MITRE techniques
    def get_mitre(cmd):
        cmd_lower = cmd.lower()
        if any(x in cmd_lower for x in ["uname", "hostname", "cat /proc", "lscpu"]):
            return "T1082 — System Information Discovery"
        elif any(x in cmd_lower for x in ["cat /etc/passwd", "id", "whoami", "w "]):
            return "T1087 — Account Discovery"
        elif any(x in cmd_lower for x in ["wget", "curl", "tftp", "ftp "]):
            return "T1105 — Ingress Tool Transfer"
        elif any(x in cmd_lower for x in ["crontab", "rc.local", "systemctl"]):
            return "T1053 — Scheduled Task/Job"
        elif any(x in cmd_lower for x in ["authorized_keys", "ssh-rsa", ".ssh"]):
            return "T1098.004 — SSH Authorized Keys"
        elif any(x in cmd_lower for x in ["chpasswd", "passwd"]):
            return "T1098 — Account Manipulation"
        elif any(x in cmd_lower for x in ["ps ", "ps aux", "top", "netstat"]):
            return "T1057 — Process Discovery"
        elif any(x in cmd_lower for x in ["rm -rf", "history -c", "unset hist"]):
            return "T1070 — Indicator Removal"
        elif any(x in cmd_lower for x in ["chmod", "chattr"]):
            return "T1222 — File Permissions Modification"
        elif any(x in cmd_lower for x in ["df ", "free ", "cat /proc/meminfo"]):
            return "T1082 — System Information Discovery"
        else:
            return "—"

    for rank, (cmd, count) in enumerate(stats["commands"].most_common(top_n), 1):
        display_cmd = cmd[:80] + "..." if len(cmd) > 80 else cmd
        # Escape pipe characters in markdown table
        display_cmd = display_cmd.replace("|", "\\|")
        mitre = get_mitre(cmd)
        lines.append(f"| {rank} | `{display_cmd}` | {count:,} | {mitre} |")

    # ── Attack Velocity ───────────────────────────────────────
    lines.append("\n## Attack Velocity\n")
    lines.append("![Attacks by Hour](charts/attacks-by-hour.png)\n")

    if stats["daily_counts"]:
        lines.append("### Daily Event Volume\n")
        lines.append("| Date | Events |")
        lines.append("|------|--------|")
        for day in sorted(stats["daily_counts"].keys()):
            lines.append(f"| {day} | {stats['daily_counts'][day]:,} |")

    # ── Protocol Breakdown ────────────────────────────────────
    if len(stats["protocols"]) > 1:
        lines.append("\n## Protocol Breakdown\n")
        lines.append("| Protocol | Events |")
        lines.append("|----------|--------|")
        for protocol, count in stats["protocols"].most_common():
            lines.append(f"| {protocol} | {count:,} |")

    # ── Top Source IPs ────────────────────────────────────────
    lines.append(f"\n## Top Source IPs\n")
    lines.append(f"| Rank | IP Address | Events | Country | ASN |")
    lines.append(f"|------|-----------|--------|---------|-----|")

    # Build IP → metadata lookup from events
    ip_meta = {}
    for session_data in stats["sessions"].values():
        ip = session_data.get("src_ip", "")
        if ip and ip not in ip_meta:
            ip_meta[ip] = {
                "country": session_data.get("country", "Unknown"),
                "asn":     session_data.get("asn", "Unknown"),
            }

    for rank, (ip, count) in enumerate(stats["src_ips"].most_common(20), 1):
        meta    = ip_meta.get(ip, {})
        country = meta.get("country", "Unknown")
        asn     = meta.get("asn", "Unknown")
        lines.append(f"| {rank} | `{ip}` | {count:,} | {country} | {asn} |")

    # Write file
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Report written to {report_path}")


def print_console_summary(stats, top_n):
    """Print a readable summary to stdout."""
    print("\n" + "=" * 60)
    print("  HONEYPOT ANALYSIS SUMMARY")
    print("=" * 60)

    print(f"\n[+] TOTALS")
    print(f"    Total events:          {stats['total_events']:,}")
    print(f"    Unique source IPs:     {len(stats['src_ips']):,}")
    print(f"    Countries:             {len(stats['countries'])}")
    print(f"    Successful logins:     {len(stats['successful_sessions']):,}")
    print(f"    Failed logins:         {stats['event_types'].get('cowrie.login.failed', 0):,}")
    print(f"    Commands executed:     {stats['event_types'].get('cowrie.command.input', 0):,}")

    print(f"\n[+] TOP 10 ATTACKER COUNTRIES")
    for country, count in stats["countries"].most_common(10):
        bar = "█" * min(40, count // max(1, max(stats["countries"].values()) // 40))
        print(f"    {count:>8,}  {bar}  {country}")

    print(f"\n[+] TOP 10 PASSWORDS")
    for pw, count in stats["passwords"].most_common(10):
        display = pw[:40] + "..." if len(pw) > 40 else pw
        print(f"    {count:>8,}  {display}")

    print(f"\n[+] TOP 10 COMMANDS")
    for cmd, count in stats["commands"].most_common(10):
        display = cmd[:60] + "..." if len(cmd) > 60 else cmd
        print(f"    {count:>8,}  {display}")

    print(f"\n[+] HASSH TOOL FINGERPRINTS")
    for hassh, count in stats["hassh_values"].most_common(10):
        tool = _lookup_hassh(hassh, stats.get("hassh_alg_map", {}).get(hassh, ""))
        print(f"    {count:>8,}  {hassh[:16]}...  {tool}")

    print("\n" + "=" * 60)


def main():
    args = parse_args()

    print("[+] analyze_sessions.py — Cowrie Honeypot Analysis")
    print(f"[+] Input:      {args.input}")
    print(f"[+] Output dir: {args.output_dir}")
    print(f"[+] Top N:      {args.top}")
    print()

    # Load and analyze
    events = load_events(args.input)
    stats  = analyze_events(events, args.top)

    # Print console summary
    print_console_summary(stats, args.top)

    # Write output files
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    write_csv_files(stats, args.output_dir, args.top)
    write_markdown_report(stats, args.output_dir, args.top)

    if not args.no_charts:
        generate_charts(stats, args.output_dir, args.top)
    else:
        print("[!] Skipping charts (--no-charts flag set)")

    print(f"\n[+] All output written to {args.output_dir}/")
    print("[+] Done.")


if __name__ == "__main__":
    main()
