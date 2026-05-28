#!/usr/bin/env python3
"""
analyze_opensearch.py — Full OpenSearch/Wazuh Dataset Analysis
==============================================================
Processes the complete 11.6M event export from OpenSearch and produces:
  - Comprehensive statistical summary for AI context
  - All charts and CSVs for the final report
  - AI-ready context file for Ollama RAG

Handles Wazuh-wrapped Cowrie field structure:
  data.eventid, data.src_ip, data.session, data.hassh, etc.

Usage:
    python analyze_opensearch.py --input data/live/opensearch_full.json
    python analyze_opensearch.py --input data/live/opensearch_full.json --no-charts
"""

import json
import argparse
import sys
import csv
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

DEFAULT_INPUT      = "data/live/opensearch_full.json"
DEFAULT_OUTPUT_DIR = "results"

# HASSH lookup
KNOWN_HASSH = {
    "f555226df1963d1d3c09daf865abdc9a": "Paramiko 2.x (Python SSH library)",
    "03a80b21afa810682a776a7d42e5e6fb": "AsyncSSH (Python async SSH framework)",
    "16443846184eafde36765c9bab2f4397": "OpenSSH 9.0-9.7 (post-quantum mlkem)",
    "af8223ac9914f509afdadfaf5f7ee94e": "OpenSSH 9.9+ (mlkem768nistp256 + sntrup761)",
    "671ac49b8bd65b9e8ff02a3e690f0fd3": "OpenSSH 8.x",
    "e54ef3ec27fe1fea7ab64d3fa05359fd": "OpenSSH 8.x",
    "19532158b559096b89b1a5f7d17175b2": "OpenSSH 8.x",
    "5f904648ee8964bef0e8834012e26003": "OpenSSH 8.x",
    "9052c4ab4164c78256e71143dcfc7eac": "OpenSSH 8.x",
    "5bd26477da5440a6187bd3f1b39a429c": "OpenSSH 8.x",
    "4e066189c3bbeec38c99b1855113733a": "OpenSSH 8.x",
    "bc9e7273cde22b1209d6673b5fd10bd5": "OpenSSH 7.x (older)",
    "2aec6b44b06bec95d73f66b5d30cb69a": "OpenSSH 7.x (older)",
    "7216c7c473918b4f83d1139b3c70dbf9": "OpenSSH 7.x (older)",
    "0a07365cc01fa9fc82608ba4019af499": "Go SSH scanner",
    "f45fb203c31069bb280067b71ed92ccb": "libssh (no curve25519)",
    "b21d7cdcc8133dc2b430d1a039fece20": "Legacy SSH library (pre-2015)",
    "dde267e50f82fcc16a7e1e7b59b8af71": "Ancient SSH client (pre-2013)",
    "a20aced7c9824fd804f59e68dd801ad3": "Dropbear SSH / IoT device",
}

def parse_args():
    p = argparse.ArgumentParser(description="Analyze full OpenSearch Wazuh export")
    p.add_argument("--input",      default=DEFAULT_INPUT)
    p.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--no-charts",  action="store_true")
    p.add_argument("--top",        type=int, default=25)
    return p.parse_args()

def extract_fields(doc):
    """Extract Cowrie fields from Wazuh-wrapped document."""
    data = doc.get("data", {})
    
    # Try full_log first (original Cowrie JSON string)
    full_log = doc.get("full_log", "")
    if full_log and isinstance(full_log, str):
        try:
            cowrie = json.loads(full_log)
            # Merge with data fields (data takes priority)
            merged = {**cowrie, **data}
            return merged
        except:
            pass
    return data

def analyze(input_path, top_n):
    print(f"[+] Loading {input_path}")
    print(f"[+] This may take a few minutes for 11M+ events...")

    # Counters
    event_types     = Counter()
    countries       = Counter()
    asns            = Counter()
    orgs            = Counter()
    src_ips         = Counter()
    usernames       = Counter()
    passwords       = Counter()
    cred_pairs      = Counter()
    commands        = Counter()
    hassh_values    = Counter()
    client_versions = Counter()
    protocols       = Counter()
    rule_ids        = Counter()
    rule_levels     = Counter()
    daily_counts    = defaultdict(int)
    hourly_counts   = defaultdict(int)
    session_durations = []
    successful_sessions = set()
    file_downloads  = []
    file_uploads    = []

    total = 0
    skipped = 0
    batch_size = 100000

    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except:
                skipped += 1
                continue

            total += 1
            if total % batch_size == 0:
                print(f"  Processed {total:>10,} events... "
                      f"({len(src_ips):,} unique IPs, "
                      f"{len(cred_pairs):,} cred pairs)")

            # Extract fields
            e = extract_fields(doc)
            eid      = e.get("eventid", "")
            src_ip   = e.get("src_ip", "")
            session  = e.get("session", "")
            ts       = doc.get("@timestamp", e.get("timestamp", ""))
            protocol = e.get("protocol", "ssh")

            # Wazuh rule info
            rule = doc.get("rule", {})
            rule_ids[rule.get("id", "unknown")] += 1
            rule_levels[rule.get("level", 0)] += 1

            event_types[eid] += 1
            protocols[protocol] += 1

            # GeoIP — from data fields
            country = e.get("src_country", "Unknown")
            asn     = e.get("src_asn", "Unknown")
            org     = e.get("src_org", "Unknown")

            if src_ip:
                src_ips[src_ip] += 1
                if country and country != "Unknown":
                    countries[country] += 1
                if asn and asn != "Unknown":
                    asns[asn] += 1
                if org and org != "Unknown":
                    orgs[org] += 1

            # Timestamp parsing
            if ts:
                try:
                    dt = datetime.fromisoformat(
                        ts.replace("Z", "+00:00").replace("+0000", "+00:00")
                    )
                    daily_counts[dt.strftime("%Y-%m-%d")] += 1
                    hourly_counts[dt.strftime("%Y-%m-%d %H:00")] += 1
                except:
                    pass

            # Event-specific
            if eid in ("cowrie.login.failed", "cowrie.login.success"):
                u = e.get("username", "")
                p = e.get("password", "")
                if u: usernames[u] += 1
                if p: passwords[p] += 1
                if u and p: cred_pairs[f"{u}:{p}"] += 1
                if eid == "cowrie.login.success":
                    successful_sessions.add(session)

            elif eid == "cowrie.command.input":
                cmd = e.get("input", "").strip()
                if cmd: commands[cmd] += 1

            elif eid == "cowrie.client.kex":
                h = e.get("hassh", "")
                if h: hassh_values[h] += 1

            elif eid == "cowrie.client.version":
                v = e.get("version", "")
                if v: client_versions[v] += 1

            elif eid == "cowrie.session.closed":
                try:
                    session_durations.append(float(e.get("duration", 0)))
                except: pass

            elif eid == "cowrie.session.file_download":
                url = e.get("url", e.get("outfile", ""))
                if url: file_downloads.append({"url": url, "ip": src_ip, "country": country})

            elif eid == "cowrie.session.file_upload":
                fname = e.get("filename", e.get("outfile", ""))
                if fname: file_uploads.append({"file": fname, "ip": src_ip, "country": country})

    print(f"\n[+] Analysis complete:")
    print(f"    Total events:          {total:>10,}")
    print(f"    Skipped (bad JSON):    {skipped:>10,}")
    print(f"    Unique source IPs:     {len(src_ips):>10,}")
    print(f"    Successful logins:     {len(successful_sessions):>10,}")
    print(f"    Countries identified:  {len(countries):>10,}")
    print(f"    Unique HASSH values:   {len(hassh_values):>10,}")
    print(f"    Unique commands:       {len(commands):>10,}")
    print(f"    Credential pairs:      {len(cred_pairs):>10,}")
    print(f"    File downloads:        {len(file_downloads):>10,}")
    print(f"    File uploads:          {len(file_uploads):>10,}")

    durations = session_durations
    avg_dur = sum(durations) / len(durations) if durations else 0
    max_dur = max(durations) if durations else 0

    return {
        "total": total,
        "skipped": skipped,
        "event_types": event_types,
        "countries": countries,
        "asns": asns,
        "orgs": orgs,
        "src_ips": src_ips,
        "usernames": usernames,
        "passwords": passwords,
        "cred_pairs": cred_pairs,
        "commands": commands,
        "hassh_values": hassh_values,
        "client_versions": client_versions,
        "protocols": protocols,
        "rule_ids": rule_ids,
        "rule_levels": rule_levels,
        "daily_counts": daily_counts,
        "hourly_counts": hourly_counts,
        "successful_sessions": successful_sessions,
        "file_downloads": file_downloads,
        "file_uploads": file_uploads,
        "avg_duration": avg_dur,
        "max_duration": max_dur,
    }

def write_csvs(stats, output_dir, top_n):
    od = Path(output_dir)
    od.mkdir(parents=True, exist_ok=True)

    # top-credentials.csv
    print("[+] Writing top-credentials.csv")
    total_creds = sum(stats["cred_pairs"].values())
    with open(od / "top-credentials.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "username", "password", "attempts", "pct_of_total"])
        for rank, (pair, count) in enumerate(stats["cred_pairs"].most_common(top_n), 1):
            u, p = pair.split(":", 1) if ":" in pair else (pair, "")
            pct = count / total_creds * 100 if total_creds else 0
            w.writerow([rank, u, p, count, f"{pct:.3f}%"])

    # attacker-countries.csv
    print("[+] Writing attacker-countries.csv")
    total_geo = sum(stats["countries"].values())
    with open(od / "attacker-countries.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "country", "events", "pct_of_total"])
        for rank, (country, count) in enumerate(stats["countries"].most_common(top_n), 1):
            pct = count / total_geo * 100 if total_geo else 0
            w.writerow([rank, country, count, f"{pct:.2f}%"])

    # file-downloads.csv
    if stats["file_downloads"]:
        print("[+] Writing file-downloads.csv")
        with open(od / "file-downloads.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "src_ip", "country"])
            for d in stats["file_downloads"][:500]:
                w.writerow([d.get("url",""), d.get("ip",""), d.get("country","")])

def generate_charts(stats, output_dir, top_n):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib not available — skipping charts")
        return

    charts_dir = Path(output_dir) / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update({"figure.facecolor": "white", "axes.facecolor": "white",
                          "axes.grid": True, "grid.alpha": 0.3})

    # Countries chart
    print("[+] Generating attacks-by-country.png")
    top = stats["countries"].most_common(15)
    if top:
        labels, values = zip(*top)
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.barh(list(reversed(labels)), list(reversed(values)), color="#E24B4A")
        ax.set_xlabel("Events")
        ax.set_title(f"Top 15 Attacker Countries — {stats['total']:,} Total Events",
                     fontweight="bold")
        for i, v in enumerate(list(reversed(values))):
            ax.text(v + max(values)*0.005, i, f"{v:,}", va="center", fontsize=8)
        plt.tight_layout()
        plt.savefig(charts_dir / "attacks-by-country.png", dpi=150)
        plt.close()

    # Daily volume chart
    print("[+] Generating attacks-by-day.png")
    if stats["daily_counts"]:
        days   = sorted(stats["daily_counts"].keys())
        counts = [stats["daily_counts"][d] for d in days]
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.bar(range(len(days)), counts, color="#185FA5")
        ax.set_xticks(range(len(days)))
        ax.set_xticklabels(days, rotation=45, ha="right")
        ax.set_ylabel("Events per Day")
        ax.set_title("Daily Attack Volume", fontweight="bold")
        for i, v in enumerate(counts):
            ax.text(i, v + max(counts)*0.01, f"{v:,}", ha="center", fontsize=8, rotation=45)
        plt.tight_layout()
        plt.savefig(charts_dir / "attacks-by-day.png", dpi=150)
        plt.close()

    # Top passwords
    print("[+] Generating top-passwords.png")
    top_pw = stats["passwords"].most_common(20)
    if top_pw:
        labels, values = zip(*top_pw)
        display = [p[:35] + "..." if len(p) > 35 else p for p in labels]
        fig, ax = plt.subplots(figsize=(12, 7))
        ax.barh(list(reversed(display)), list(reversed(values)), color="#185FA5")
        ax.set_xlabel("Attempts")
        ax.set_title("Top 20 Attempted Passwords", fontweight="bold")
        plt.tight_layout()
        plt.savefig(charts_dir / "top-passwords.png", dpi=150)
        plt.close()

    # Top usernames
    print("[+] Generating top-usernames.png")
    top_un = stats["usernames"].most_common(20)
    if top_un:
        labels, values = zip(*top_un)
        display = [u[:35] + "..." if len(u) > 35 else u for u in labels]
        fig, ax = plt.subplots(figsize=(12, 7))
        ax.barh(list(reversed(display)), list(reversed(values)), color="#BA7517")
        ax.set_xlabel("Attempts")
        ax.set_title("Top 20 Attempted Usernames", fontweight="bold")
        plt.tight_layout()
        plt.savefig(charts_dir / "top-usernames.png", dpi=150)
        plt.close()

    # HASSH distribution
    print("[+] Generating hassh-distribution.png")
    top_h = stats["hassh_values"].most_common(10)
    if top_h:
        labels = [KNOWN_HASSH.get(h, h[:16]+"...") for h, _ in top_h]
        values = [c for _, c in top_h]
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.barh(list(reversed(labels)), list(reversed(values)), color="#1D9E75")
        ax.set_xlabel("Sessions")
        ax.set_title("SSH Tool Fingerprints (HASSH)", fontweight="bold")
        plt.tight_layout()
        plt.savefig(charts_dir / "hassh-distribution.png", dpi=150)
        plt.close()

    print(f"[+] Charts saved to {charts_dir}/")

def write_ai_context(stats, output_dir, top_n):
    """Write a comprehensive AI context file for RAG/Ollama ingestion."""
    print("[+] Writing ai-context.md (Ollama training context)")
    od = Path(output_dir)

    lines = []
    lines.append("# Honeypot Intelligence Report — AI Context Document")
    lines.append(f"\nGenerated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"Dataset: {stats['total']:,} Wazuh alerts from 6-day honeypot capture\n")
    lines.append("---\n")

    # Summary stats
    lines.append("## Summary Statistics\n")
    lines.append(f"- Total events: {stats['total']:,}")
    lines.append(f"- Unique attacker IPs: {len(stats['src_ips']):,}")
    lines.append(f"- Countries: {len(stats['countries'])}")
    lines.append(f"- Successful honeypot logins: {len(stats['successful_sessions']):,}")
    lines.append(f"- Failed login attempts: {stats['event_types'].get('cowrie.login.failed', 0):,}")
    lines.append(f"- Commands executed in fake shell: {stats['event_types'].get('cowrie.command.input', 0):,}")
    lines.append(f"- File downloads attempted: {stats['event_types'].get('cowrie.session.file_download', 0):,}")
    lines.append(f"- File uploads attempted: {stats['event_types'].get('cowrie.session.file_upload', 0):,}")
    lines.append(f"- Unique credential pairs: {len(stats['cred_pairs']):,}")
    lines.append(f"- Unique HASSH fingerprints: {len(stats['hassh_values'])}")
    lines.append(f"- Average session duration: {stats['avg_duration']:.1f}s")
    lines.append(f"- Longest session: {stats['max_duration']:.1f}s\n")

    # Event breakdown
    lines.append("## Event Type Breakdown\n")
    for eid, count in stats["event_types"].most_common():
        lines.append(f"- {eid}: {count:,}")
    lines.append("")

    # Geography
    lines.append(f"## Top {min(top_n, len(stats['countries']))} Attacker Countries\n")
    total_geo = sum(stats["countries"].values())
    for rank, (country, count) in enumerate(stats["countries"].most_common(top_n), 1):
        pct = count / total_geo * 100 if total_geo else 0
        lines.append(f"{rank}. {country}: {count:,} events ({pct:.1f}%)")
    lines.append("")

    # Top ASNs
    lines.append(f"## Top {min(20, len(stats['asns']))} Attacker ASNs (Infrastructure)\n")
    for rank, (asn, count) in enumerate(stats["asns"].most_common(20), 1):
        org = ""
        for o, c in stats["orgs"].most_common(100):
            pass
        lines.append(f"{rank}. {asn}: {count:,} events")
    lines.append("")

    # Credentials
    lines.append(f"## Top {min(top_n, len(stats['passwords']))} Attempted Passwords\n")
    for rank, (pw, count) in enumerate(stats["passwords"].most_common(top_n), 1):
        display = pw[:60] + "..." if len(pw) > 60 else pw
        lines.append(f"{rank}. `{display}`: {count:,} attempts")
    lines.append("")

    lines.append(f"## Top {min(top_n, len(stats['usernames']))} Attempted Usernames\n")
    for rank, (u, count) in enumerate(stats["usernames"].most_common(top_n), 1):
        lines.append(f"{rank}. `{u}`: {count:,} attempts")
    lines.append("")

    lines.append(f"## Top {min(top_n, len(stats['cred_pairs']))} Credential Pairs\n")
    for rank, (pair, count) in enumerate(stats["cred_pairs"].most_common(top_n), 1):
        u, p = pair.split(":", 1) if ":" in pair else (pair, "")
        lines.append(f"{rank}. `{u}` / `{p}`: {count:,} attempts")
    lines.append("")

    # Commands
    lines.append(f"## Top {min(top_n, len(stats['commands']))} Commands Executed\n")
    for rank, (cmd, count) in enumerate(stats["commands"].most_common(top_n), 1):
        display = cmd[:100] + "..." if len(cmd) > 100 else cmd
        display = display.replace("|", "\\|")
        lines.append(f"{rank}. ({count:,}x) `{display}`")
    lines.append("")

    # HASSH
    lines.append("## SSH Tool Fingerprints (HASSH)\n")
    for rank, (h, count) in enumerate(stats["hassh_values"].most_common(20), 1):
        tool = KNOWN_HASSH.get(h, "Unknown tool")
        lines.append(f"{rank}. {tool} — `{h}`: {count:,} sessions")
    lines.append("")

    # File downloads
    if stats["file_downloads"]:
        lines.append("## File Downloads Attempted (Malware Delivery)\n")
        url_counter = Counter(d.get("url","") for d in stats["file_downloads"])
        for rank, (url, count) in enumerate(url_counter.most_common(20), 1):
            lines.append(f"{rank}. ({count:,}x) `{url[:120]}`")
        lines.append("")

    # Daily breakdown
    lines.append("## Daily Event Volume\n")
    for day in sorted(stats["daily_counts"].keys()):
        lines.append(f"- {day}: {stats['daily_counts'][day]:,} events")
    lines.append("")

    # Wazuh rule breakdown
    lines.append("## Wazuh Alert Severity Distribution\n")
    for level in sorted(stats["rule_levels"].keys(), reverse=True):
        count = stats["rule_levels"][level]
        label = {12: "CRITICAL", 10: "HIGH", 8: "MEDIUM-HIGH",
                 6: "MEDIUM", 3: "LOW"}.get(level, f"Level {level}")
        lines.append(f"- {label} (Level {level}): {count:,} alerts")
    lines.append("")

    with open(od / "ai-context.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] AI context written to {od}/ai-context.md")

def write_markdown_report(stats, output_dir, top_n):
    """Write the final attack-analysis.md report."""
    print("[+] Writing attack-analysis.md")
    od = Path(output_dir)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Attack Analysis Report — Honeypot Deployment")
    lines.append(f"\n> Generated: {now}  ")
    lines.append(f"> Dataset: Full 6-day OpenSearch export — {stats['total']:,} Wazuh alerts  ")
    lines.append(f"> Script: `analysis/analyze_sessions.py`\n")

    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total events | {stats['total']:,} |")
    lines.append(f"| Unique source IPs | {len(stats['src_ips']):,} |")
    lines.append(f"| Countries represented | {len(stats['countries'])} |")
    lines.append(f"| Successful logins | {len(stats['successful_sessions']):,} |")
    lines.append(f"| Failed login attempts | {stats['event_types'].get('cowrie.login.failed', 0):,} |")
    lines.append(f"| Commands executed | {stats['event_types'].get('cowrie.command.input', 0):,} |")
    lines.append(f"| File downloads attempted | {stats['event_types'].get('cowrie.session.file_download', 0):,} |")
    lines.append(f"| File uploads attempted | {stats['event_types'].get('cowrie.session.file_upload', 0):,} |")
    lines.append(f"| Unique credential pairs | {len(stats['cred_pairs']):,} |")
    lines.append(f"| Unique HASSH fingerprints | {len(stats['hassh_values'])} |")
    lines.append(f"| Avg session duration | {stats['avg_duration']:.1f}s |")
    lines.append(f"| Longest session | {stats['max_duration']:.1f}s |\n")

    lines.append("## Geographic Analysis\n")
    lines.append("![Attacks by Country](charts/attacks-by-country.png)\n")
    lines.append("| Rank | Country | Events | % of Geo-Tagged |")
    lines.append("|------|---------|--------|----------------|")
    total_geo = sum(stats["countries"].values())
    for rank, (country, count) in enumerate(stats["countries"].most_common(top_n), 1):
        pct = count / total_geo * 100 if total_geo else 0
        lines.append(f"| {rank} | {country} | {count:,} | {pct:.1f}% |")

    lines.append("\n## Credential Analysis\n")
    lines.append("![Top Passwords](charts/top-passwords.png)\n")
    lines.append(f"### Top {min(top_n, len(stats['passwords']))} Passwords\n")
    lines.append("| Rank | Password | Attempts |")
    lines.append("|------|----------|---------|")
    for rank, (pw, count) in enumerate(stats["passwords"].most_common(top_n), 1):
        display = pw[:60] + "..." if len(pw) > 60 else pw
        lines.append(f"| {rank} | `{display}` | {count:,} |")

    lines.append(f"\n### Top {min(top_n, len(stats['usernames']))} Usernames\n")
    lines.append("| Rank | Username | Attempts |")
    lines.append("|------|----------|---------|")
    for rank, (u, count) in enumerate(stats["usernames"].most_common(top_n), 1):
        lines.append(f"| {rank} | `{u}` | {count:,} |")

    lines.append(f"\n### Top {min(top_n, len(stats['cred_pairs']))} Credential Pairs\n")
    lines.append("| Rank | Username | Password | Attempts |")
    lines.append("|------|----------|----------|---------|")
    for rank, (pair, count) in enumerate(stats["cred_pairs"].most_common(top_n), 1):
        u, p = pair.split(":", 1) if ":" in pair else (pair, "")
        display_p = p[:40] + "..." if len(p) > 40 else p
        lines.append(f"| {rank} | `{u}` | `{display_p}` | {count:,} |")

    lines.append("\n## HASSH Tool Fingerprints\n")
    lines.append("![HASSH Distribution](charts/hassh-distribution.png)\n")
    lines.append("| Rank | Tool | HASSH | Sessions |")
    lines.append("|------|------|-------|---------|")
    for rank, (h, count) in enumerate(stats["hassh_values"].most_common(20), 1):
        tool = KNOWN_HASSH.get(h, "Unknown tool")
        lines.append(f"| {rank} | {tool} | `{h[:16]}...` | {count:,} |")

    lines.append("\n## Command Analysis\n")
    lines.append("| Rank | Command | Executions |")
    lines.append("|------|---------|-----------|")
    for rank, (cmd, count) in enumerate(stats["commands"].most_common(top_n), 1):
        display = cmd[:80] + "..." if len(cmd) > 80 else cmd
        display = display.replace("|", "\\|")
        lines.append(f"| {rank} | `{display}` | {count:,} |")

    if stats["file_downloads"]:
        lines.append("\n## File Downloads (Malware Delivery Attempts)\n")
        lines.append("| URL | Count |")
        lines.append("|-----|-------|")
        url_counter = Counter(d.get("url","") for d in stats["file_downloads"])
        for url, count in url_counter.most_common(20):
            lines.append(f"| `{url[:100]}` | {count:,} |")

    lines.append("\n## Daily Attack Volume\n")
    lines.append("![Daily Volume](charts/attacks-by-day.png)\n")
    lines.append("| Date | Events |")
    lines.append("|------|--------|")
    for day in sorted(stats["daily_counts"].keys()):
        lines.append(f"| {day} | {stats['daily_counts'][day]:,} |")

    with open(od / "attack-analysis.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Report written to {od}/attack-analysis.md")

def print_console_summary(stats, top_n):
    print("\n" + "=" * 60)
    print("  FULL DATASET ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"\n  Total events:      {stats['total']:>12,}")
    print(f"  Unique IPs:        {len(stats['src_ips']):>12,}")
    print(f"  Countries:         {len(stats['countries']):>12,}")
    print(f"  Successful logins: {len(stats['successful_sessions']):>12,}")
    print(f"  Failed logins:     {stats['event_types'].get('cowrie.login.failed',0):>12,}")
    print(f"  Commands:          {stats['event_types'].get('cowrie.command.input',0):>12,}")
    print(f"  File downloads:    {stats['event_types'].get('cowrie.session.file_download',0):>12,}")
    print(f"  Cred pairs:        {len(stats['cred_pairs']):>12,}")

    print(f"\n  TOP 10 COUNTRIES")
    for c, n in stats["countries"].most_common(10):
        bar = "█" * min(30, n // max(1, max(stats["countries"].values()) // 30))
        print(f"  {n:>10,}  {bar}  {c}")

    print(f"\n  TOP 10 PASSWORDS")
    for pw, n in stats["passwords"].most_common(10):
        display = pw[:40] + "..." if len(pw) > 40 else pw
        print(f"  {n:>10,}  {display}")

    print(f"\n  TOP 10 COMMANDS")
    for cmd, n in stats["commands"].most_common(10):
        display = cmd[:60] + "..." if len(cmd) > 60 else cmd
        print(f"  {n:>10,}  {display}")

    print(f"\n  HASSH TOOL FINGERPRINTS")
    for h, n in stats["hassh_values"].most_common(10):
        tool = KNOWN_HASSH.get(h, "Unknown")
        print(f"  {n:>10,}  {tool}")

    print("\n" + "=" * 60)

def main():
    args = parse_args()
    print("[+] analyze_opensearch.py — Full Dataset Analysis")
    print(f"[+] Input:      {args.input}")
    print(f"[+] Output dir: {args.output_dir}")
    print()

    stats = analyze(args.input, args.top)
    print_console_summary(stats, args.top)

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    write_csvs(stats, args.output_dir, args.top)
    write_markdown_report(stats, args.output_dir, args.top)
    write_ai_context(stats, args.output_dir, args.top)

    if not args.no_charts:
        generate_charts(stats, args.output_dir, args.top)

    print(f"\n[+] All output written to {args.output_dir}/")
    print("[+] Done.")

if __name__ == "__main__":
    main()
