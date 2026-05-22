#!/usr/bin/env python3
"""
explain_sessions.py — LLM-Powered Session Explainer
=====================================================
Feeds Cowrie honeypot session transcripts to a local Ollama LLM and generates
plain-English explanations of attacker behavior. Produces session-explanations.md
in the same format as Project 2's explanations.md (ai-traffic-classifier).

Follows the same code patterns as Project 2:
- argparse for CLI flexibility
- [+] progress output
- Ollama llama3.1:8b (local, RTX 4070)
- Structured markdown output

Usage:
    # Run on Alienware (where Ollama is installed)
    python3 explain_sessions.py
    python3 explain_sessions.py --input /path/to/cowrie_enriched.json
    python3 explain_sessions.py --sessions 5 --categories all
    python3 explain_sessions.py --sessions 3 --categories implant,recon,bruteforce

Categories:
    implant      — SSH key backdoor implant sessions
    recon        — System reconnaissance sessions
    bruteforce   — Credential brute force attempts
    cryptominer  — Cryptomining reconnaissance
    webattack    — nginx web attack sessions (reads nginx access.log)
    all          — All categories (default)

Dependencies:
    pip install requests  (for Ollama API)
    Ollama running locally with llama3.1:8b pulled:
        ollama pull llama3.1:8b

Output:
    results/session-explanations.md

Model: llama3.1:8b (local, Alienware RTX 4070)
"""

import json
import argparse
import sys
import os
import requests
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

# ============================================================
# Configuration
# ============================================================
DEFAULT_INPUT        = "/opt/cowrie-logs/cowrie_enriched.json"
DEFAULT_NGINX_INPUT  = "/opt/cowrie-logs/nginx/access.log"
DEFAULT_OUTPUT_DIR   = str(Path(__file__).parent.parent / "results")
OLLAMA_URL           = "http://localhost:11434/api/generate"
OLLAMA_MODEL         = "llama3.1:8b"
DEFAULT_SESSIONS     = 2   # Explanations per category (matches Project 2: 2 flows per scenario)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate LLM explanations of honeypot attack sessions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 explain_sessions.py
  python3 explain_sessions.py --sessions 3 --categories implant,recon
  python3 explain_sessions.py --input /opt/cowrie-logs/cowrie_enriched.json
  python3 explain_sessions.py --ollama-url http://192.168.10.x:11434/api/generate
        """
    )
    parser.add_argument("--input", default=DEFAULT_INPUT,
                        help=f"Cowrie enriched JSON log (default: {DEFAULT_INPUT})")
    parser.add_argument("--nginx-input", default=DEFAULT_NGINX_INPUT,
                        help=f"nginx access log (default: {DEFAULT_NGINX_INPUT})")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--sessions", type=int, default=DEFAULT_SESSIONS,
                        help=f"Sessions to explain per category (default: {DEFAULT_SESSIONS})")
    parser.add_argument("--categories", default="all",
                        help="Categories: implant,recon,bruteforce,cryptominer,webattack,all")
    parser.add_argument("--ollama-url", default=OLLAMA_URL,
                        help=f"Ollama API URL (default: {OLLAMA_URL})")
    parser.add_argument("--model", default=OLLAMA_MODEL,
                        help=f"Ollama model (default: {OLLAMA_MODEL})")
    return parser.parse_args()


def check_ollama(url, model):
    """Verify Ollama is running and model is available."""
    try:
        resp = requests.get(url.replace("/api/generate", "/api/tags"), timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            if any(model in m for m in models):
                print(f"[+] Ollama running — model {model} available")
                return True
            else:
                print(f"[-] Model {model} not found. Available: {models}")
                print(f"    Run: ollama pull {model}")
                return False
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot connect to Ollama at {url}")
        print(f"    Make sure Ollama is running: ollama serve")
        return False
    return False


def load_sessions(input_path):
    """Load and group events by session ID."""
    print(f"[+] Loading sessions from {input_path}")

    sessions = defaultdict(list)
    skipped  = 0

    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                sid = event.get("session", "")
                if sid:
                    sessions[sid].append(event)
            except json.JSONDecodeError:
                skipped += 1

    print(f"[+] Loaded {len(sessions):,} sessions ({skipped} skipped lines)")
    return sessions


def categorize_sessions(sessions):
    """
    Categorize sessions by attack type.
    Returns dict of category -> list of (session_id, events) tuples.
    """
    categories = defaultdict(list)

    for sid, events in sessions.items():
        event_ids = [e.get("eventid", "") for e in events]
        commands  = [e.get("input", "") for e in events
                     if e.get("eventid") == "cowrie.command.input"]
        has_login = "cowrie.login.success" in event_ids
        has_fail  = "cowrie.login.failed" in event_ids
        has_cmd   = "cowrie.command.input" in event_ids

        # SSH key implant — the dominant attack pattern
        if has_login and has_cmd:
            cmd_text = " ".join(commands).lower()
            if "authorized_keys" in cmd_text or "ssh-rsa" in cmd_text:
                categories["implant"].append((sid, events))
                continue

            # Cryptominer recon — checks CPU/memory before deploying miner
            if any(x in cmd_text for x in ["cpuinfo", "proc/cpu", "free -m",
                                             "nproc", "lscpu"]):
                categories["cryptominer"].append((sid, events))
                continue

            # System recon — uname, passwd, process listing
            if any(x in cmd_text for x in ["uname", "passwd", "ps aux",
                                             "whoami", "id ", "hostname"]):
                categories["recon"].append((sid, events))
                continue

            # Generic post-login
            categories["recon"].append((sid, events))

        # Pure brute force — many failed logins, no success
        elif has_fail and not has_login:
            fail_count = sum(1 for e in events
                             if e.get("eventid") == "cowrie.login.failed")
            if fail_count >= 3:
                categories["bruteforce"].append((sid, events))

    return categories


def build_session_transcript(events):
    """Build a readable transcript from session events."""
    lines = []
    meta  = {}

    for event in sorted(events, key=lambda x: x.get("timestamp", "")):
        eid = event.get("eventid", "")

        if eid == "cowrie.session.connect":
            meta["src_ip"]      = event.get("src_ip", "unknown")
            meta["country"]     = event.get("src_country", "unknown")
            meta["city"]        = event.get("src_city", "unknown")
            meta["asn"]         = event.get("src_asn", "unknown")
            meta["org"]         = event.get("src_org", "unknown")
            meta["protocol"]    = event.get("protocol", "ssh")
            meta["timestamp"]   = event.get("timestamp", "")

        elif eid == "cowrie.client.version":
            meta["client_version"] = event.get("version", "unknown")

        elif eid == "cowrie.client.kex":
            meta["hassh"] = event.get("hassh", "unknown")

        elif eid == "cowrie.login.failed":
            lines.append(f"FAILED LOGIN: {event.get('username')} / {event.get('password')}")

        elif eid == "cowrie.login.success":
            lines.append(f"SUCCESSFUL LOGIN: {event.get('username')} / {event.get('password')}")

        elif eid == "cowrie.command.input":
            cmd = event.get("input", "").strip()
            # Truncate very long commands for readability
            if len(cmd) > 200:
                cmd = cmd[:200] + "... [truncated]"
            lines.append(f"COMMAND: {cmd}")

        elif eid == "cowrie.session.closed":
            meta["duration"] = event.get("duration", "unknown")

    return meta, lines


def ask_ollama(prompt, url, model):
    """Send a prompt to Ollama and return the response."""
    payload = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,  # Lower = more consistent, factual responses
            "num_predict": 400,  # Max tokens per explanation
        }
    }

    try:
        resp = requests.post(url, json=payload, timeout=120)
        if resp.status_code == 200:
            return resp.json().get("response", "").strip()
        else:
            return f"[Error: HTTP {resp.status_code}]"
    except requests.exceptions.Timeout:
        return "[Error: Ollama timeout — try reducing --sessions]"
    except requests.exceptions.ConnectionError:
        return "[Error: Cannot connect to Ollama]"


def explain_session(meta, transcript, category, url, model):
    """Generate LLM explanation for a single session."""

    transcript_text = "\n".join(transcript) if transcript else "No commands recorded"

    prompt = f"""You are a cybersecurity analyst reviewing data captured by an SSH honeypot.
Analyze this attack session and provide a concise professional explanation.

ATTACK SESSION DATA:
- Source IP: {meta.get('src_ip', 'unknown')}
- Country: {meta.get('country', 'unknown')} / {meta.get('city', 'unknown')}
- Organization: {meta.get('org', 'unknown')} ({meta.get('asn', 'unknown')})
- Protocol: {meta.get('protocol', 'ssh')}
- SSH Client: {meta.get('client_version', 'unknown')}
- HASSH Fingerprint: {meta.get('hassh', 'unknown')}
- Session Duration: {meta.get('duration', 'unknown')} seconds
- Attack Category: {category}

SESSION TRANSCRIPT:
{transcript_text}

Provide a structured analysis with these sections:
1. Attack Behavior: What did the attacker do and why?
2. Tool Identification: What tool/method are they using based on the evidence?
3. Attacker Intent: What were they trying to achieve?
4. Key Indicators: The 2-3 most significant forensic indicators in this session.
5. MITRE ATT&CK: Which technique(s) does this map to? (provide IDs)

Keep each section to 2-3 sentences. Be specific and factual."""

    return ask_ollama(prompt, url, model)


def load_nginx_sessions(nginx_path, max_sessions=10):
    """Load interesting nginx sessions for web attack explanation."""
    if not Path(nginx_path).exists():
        return []

    interesting = []
    seen_paths  = set()

    high_value_patterns = [
        ".env", ".git", "wp-login", "cgi-bin", "jndi:",
        "phpmyadmin", "admin", "actuator", "invoker",
        "passwd", "config", "backup", ".php"
    ]

    try:
        with open(nginx_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Parse nginx combined log format
                parts = line.split('"')
                if len(parts) < 3:
                    continue
                request = parts[1] if len(parts) > 1 else ""
                path    = request.split()[1] if len(request.split()) > 1 else ""

                if any(p in path.lower() for p in high_value_patterns):
                    if path not in seen_paths:
                        seen_paths.add(path)
                        interesting.append({
                            "raw":     line,
                            "request": request,
                            "path":    path
                        })
                        if len(interesting) >= max_sessions:
                            break
    except IOError:
        pass

    return interesting


def explain_web_session(session_data, url, model):
    """Generate explanation for a web attack."""
    prompt = f"""You are a cybersecurity analyst reviewing data from a web honeypot (nginx).
Analyze this HTTP request and provide a concise professional explanation.

RAW REQUEST LOG:
{session_data['raw']}

REQUEST: {session_data['request']}

Provide a structured analysis:
1. Attack Type: What vulnerability or weakness is being probed?
2. Tool/Scanner: What tool likely generated this request?
3. CVE or Technique: Is this targeting a known CVE? Provide the CVE ID if known.
4. MITRE ATT&CK: Which technique does this map to? (provide ID)
5. Defender Action: What one defensive measure would prevent this?

Keep each section to 1-2 sentences. Be specific."""

    return ask_ollama(prompt, url, model)


def write_markdown_report(all_explanations, output_dir, args):
    """Write the session explanations markdown file."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "session-explanations.md"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Session Explanations — Ollama LLM Analysis")
    lines.append(f"\n> Generated: {now}  ")
    lines.append(f"> Model: {args.model} (local, Alienware RTX 4070)  ")
    lines.append(f"> Input: Cowrie honeypot session data  ")
    lines.append(f"> Script: `analysis/explain_sessions.py`\n")
    lines.append("Plain-English explanations of representative attack sessions,")
    lines.append("generated by a local LLM. Mirrors the format of Project 2's")
    lines.append("`results/explanations.md` (ai-traffic-classifier).\n")
    lines.append("---\n")

    category_labels = {
        "implant":     "SSH Key Backdoor Implant",
        "recon":       "System Reconnaissance",
        "bruteforce":  "Credential Brute Force",
        "cryptominer": "Cryptominer Reconnaissance",
        "webattack":   "Web Attack (nginx)",
    }

    for category, sessions in all_explanations.items():
        label = category_labels.get(category, category.title())
        lines.append(f"## {label}\n")

        # Category description
        descriptions = {
            "implant":     "Attacker logs in and immediately attempts to install a persistent SSH backdoor by injecting their public key into `~/.ssh/authorized_keys`. This gives them permanent access even after the password is changed.",
            "recon":       "Attacker logs in and runs system enumeration commands to assess the target before deciding on next steps. Classic pre-exploitation intelligence gathering.",
            "bruteforce":  "Automated tool cycling through credential lists without achieving a successful login. Generates high event volume with no post-login activity.",
            "cryptominer": "Attacker checks system resources (CPU cores, memory, architecture) to determine if the server is profitable for cryptocurrency mining before deploying a miner.",
            "webattack":   "Automated scanner or exploit tool probing the web server for known vulnerabilities, exposed configuration files, or exploitable endpoints.",
        }
        if category in descriptions:
            lines.append(f"**Attack type:** {descriptions[category]}\n")

        for i, (session_info, explanation) in enumerate(sessions, 1):
            meta       = session_info.get("meta", {})
            transcript = session_info.get("transcript", [])

            lines.append(f"### Session #{i}\n")

            # Session metadata table
            lines.append("**Session Metadata:**\n")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| Source IP | `{meta.get('src_ip', 'unknown')}` |")
            lines.append(f"| Country | {meta.get('country', 'unknown')} |")
            lines.append(f"| Organization | {meta.get('org', 'unknown')} |")
            lines.append(f"| ASN | `{meta.get('asn', 'unknown')}` |")
            lines.append(f"| SSH Client | `{meta.get('client_version', 'unknown')}` |")
            lines.append(f"| HASSH | `{meta.get('hassh', 'unknown')}` |")
            lines.append(f"| Duration | {meta.get('duration', '?')}s |")
            lines.append(f"| Timestamp | {meta.get('timestamp', 'unknown')} |\n")

            # Transcript
            if transcript:
                lines.append("**Session Transcript:**\n")
                lines.append("```")
                for line in transcript:
                    lines.append(line)
                lines.append("```\n")

            # LLM explanation
            lines.append("**Analysis:**\n")
            lines.append(explanation)
            lines.append("\n---\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Report written to {output_path}")
    return output_path


def main():
    args = parse_args()

    print("[+] explain_sessions.py — Cowrie Honeypot Session Explainer")
    print(f"[+] Model:      {args.model}")
    print(f"[+] Input:      {args.input}")
    print(f"[+] Output dir: {args.output_dir}")
    print(f"[+] Sessions per category: {args.sessions}")
    print()

    # Check Ollama is available
    if not check_ollama(args.ollama_url, args.model):
        sys.exit(1)

    # Parse categories
    if args.categories == "all":
        selected = ["implant", "recon", "bruteforce", "cryptominer", "webattack"]
    else:
        selected = [c.strip() for c in args.categories.split(",")]

    print(f"[+] Categories: {', '.join(selected)}")
    print()

    # Load and categorize sessions
    sessions    = load_sessions(args.input)
    categorized = categorize_sessions(sessions)

    print(f"[+] Session categories found:")
    for cat, sess_list in categorized.items():
        print(f"    {cat:15} {len(sess_list):>5} sessions")
    print()

    # Generate explanations
    all_explanations = {}

    for category in selected:
        if category == "webattack":
            # Handle nginx separately
            print(f"[+] Processing web attacks from nginx log...")
            web_sessions = load_nginx_sessions(args.nginx_input, args.sessions)
            if not web_sessions:
                print(f"    [!] No web sessions found at {args.nginx_input}")
                continue

            explanations = []
            for i, sess in enumerate(web_sessions[:args.sessions], 1):
                print(f"    Explaining web session {i}/{min(args.sessions, len(web_sessions))}...")
                explanation = explain_web_session(sess, args.ollama_url, args.model)
                session_info = {
                    "meta": {
                        "src_ip":   sess["raw"].split()[0],
                        "protocol": "http",
                        "duration": "N/A",
                    },
                    "transcript": [sess["request"]]
                }
                explanations.append((session_info, explanation))
                print(f"    [+] Done")

            all_explanations["webattack"] = explanations
            continue

        sess_list = categorized.get(category, [])
        if not sess_list:
            print(f"[!] No {category} sessions found — skipping")
            continue

        print(f"[+] Processing {category} — {len(sess_list)} sessions available, explaining {min(args.sessions, len(sess_list))}")

        explanations = []
        for i, (sid, events) in enumerate(sess_list[:args.sessions], 1):
            meta, transcript = build_session_transcript(events)
            print(f"    Session {i}/{min(args.sessions, len(sess_list))}: {sid[:12]}... "
                  f"({meta.get('country', '?')}, {len(transcript)} events)")

            explanation = explain_session(meta, transcript, category, args.ollama_url, args.model)
            session_info = {"meta": meta, "transcript": transcript}
            explanations.append((session_info, explanation))
            print(f"    [+] Explained")

        all_explanations[category] = explanations
        print()

    # Write report
    if all_explanations:
        output_path = write_markdown_report(all_explanations, args.output_dir, args)
        print(f"\n[+] Session explanations complete")
        print(f"[+] Output: {output_path}")
    else:
        print("[-] No explanations generated")

    print("[+] Done.")


if __name__ == "__main__":
    main()
