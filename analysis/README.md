# Analysis

Python scripts for analyzing Cowrie honeypot session data and generating the attack intelligence report. These scripts run after the capture period ends on May 28, 2026.

---

## Scripts

### `analyze_sessions.py` — Main Analysis Script

Reads GeoIP-enriched Cowrie JSON logs and produces a full attack intelligence report: credential analysis, geographic breakdown, HASSH tool fingerprinting, command analysis, session statistics, and attack velocity charts.

```bash
# UBUNTU SERVER or ALIENWARE
# Reads from Ubuntu Server, outputs to local results/

python3 analyze_sessions.py \
  --input /opt/cowrie-logs/cowrie_enriched.json \
  --output-dir ../results \
  --top 25

# Skip charts if matplotlib not installed
python3 analyze_sessions.py --no-charts

# Show top 50 entries in all tables
python3 analyze_sessions.py --top 50
```

**Input:** `/opt/cowrie-logs/cowrie_enriched.json`  
**Output directory:** `results/`

Output files:

| File | Contents |
|------|---------|
| `results/attack-analysis.md` | Full markdown analysis report |
| `results/top-credentials.csv` | Top username/password pairs |
| `results/attacker-countries.csv` | Country breakdown with event counts |
| `results/charts/attacks-by-country.png` | Geographic distribution chart |
| `results/charts/attacks-by-hour.png` | Attack velocity timeline |
| `results/charts/top-passwords.png` | Top attempted passwords |
| `results/charts/top-usernames.png` | Top attempted usernames |

**Dependencies:**
```bash
pip3 install matplotlib --break-system-packages
```

**HASSH identification:** Imports `pipeline/hassh_identify.py` automatically. Uses the persistent cache at `/opt/geoip/hassh_cache.json` for tool identification — no hardcoded lookup table.

**24-hour test results:**

```
Total events:        8,090
Unique source IPs:     176
Countries:              50
Successful logins:     466
Failed logins:         541
Commands executed:     490
Unique HASSH values:    19
Credential pairs:      428
```

---

### `explain_sessions.py` — LLM Session Explainer

Feeds Cowrie session transcripts to a local Ollama LLM and generates plain-English explanations of attacker behavior. Runs on Alienware (where Ollama is installed). Mirrors the format of Project 2's `explain.py` (ai-traffic-classifier).

```bash
# ALIENWARE — requires Ollama with llama3.1:8b
ollama pull llama3.1:8b  # if not already pulled

python analyze_sessions.py \
  --input C:\path\to\cowrie_enriched.json \
  --nginx-input C:\path\to\nginx_access.log \
  --output-dir results \
  --sessions 2 \
  --categories implant,recon,cryptominer

# All categories
python analyze_sessions.py --categories all
```

**Input:** `cowrie_enriched.json` (copy from Ubuntu Server)  
**Output:** `results/session-explanations.md`  
**Model:** `llama3.1:8b` (local, Alienware RTX 4070)  
**Ollama URL:** `http://localhost:11434/api/generate`

Categories:

| Category | Description | MITRE |
|----------|-------------|-------|
| `implant` | SSH key backdoor installation | T1098.004 |
| `recon` | System reconnaissance commands | T1082, T1087 |
| `bruteforce` | Credential brute force attempts | T1110.001 |
| `cryptominer` | Cryptomining resource reconnaissance | T1082 |
| `webattack` | nginx web attack sessions | T1190 |

**Dependencies:**
```bash
pip install requests
# Ollama running: ollama serve
```

**Sample output (generated May 22, 2026):**

The LLM correctly identified:
- SSH key implant campaign as persistent backdoor attempt (T1098.004)
- `chattr -ia` as anti-forensics / file attribute manipulation (T1222)
- Paramiko tool spoofing OpenSSH version string in client banner
- BusyBox probing as IoT device fingerprinting

---

## Running the Full Analysis Pipeline

After capture ends May 28, 2026:

**Step 1 — Pull final enriched data to Alienware:**

```powershell
# ALIENWARE (PowerShell)
scp terickson@100.82.166.75:/opt/cowrie-logs/cowrie_enriched.json C:\Users\tycee\Downloads\cowrie_enriched.json
scp terickson@100.82.166.75:/opt/cowrie-logs/nginx/access.log C:\Users\tycee\Downloads\nginx_access.log
```

**Step 2 — Run main analysis:**

```bash
# UBUNTU SERVER
python3 /opt/cowrie-tools/analyze_sessions.py \
  --input /opt/cowrie-logs/cowrie_enriched.json \
  --output-dir /opt/cowrie-tools/results \
  --top 25
```

**Step 3 — Run LLM explainer:**

```powershell
# ALIENWARE
python analysis\explain_sessions.py `
  --input C:\Users\tycee\Downloads\cowrie_enriched.json `
  --nginx-input C:\Users\tycee\Downloads\nginx_access.log `
  --output-dir results `
  --sessions 3 `
  --categories all
```

**Step 4 — Pull results back and commit:**

```powershell
# ALIENWARE
scp -r terickson@100.82.166.75:/opt/cowrie-tools/results/ C:\Users\tycee\cowrie-honeypot-git\results\
cd C:\Users\tycee\cowrie-honeypot-git
git add .
git commit -m "M4: final analysis — 7-day capture results"
git push origin main
```

---

## MITRE ATT&CK Coverage

Techniques observed and analyzed in this project:

| Technique | ID | Source |
|-----------|-----|--------|
| Network Service Discovery | T1046 | Cowrie connection events |
| Brute Force: Password Guessing | T1110.001 | Cowrie login.failed |
| Valid Accounts | T1078 | Cowrie login.success |
| Command and Scripting Interpreter | T1059 | Cowrie command.input |
| System Information Discovery | T1082 | Post-login uname/cpuinfo commands |
| SSH Authorized Keys | T1098.004 | SSH key implant campaign (225+ sessions) |
| Ingress Tool Transfer | T1105 | wget/curl download attempts |
| Exploit Public-Facing Application | T1190 | nginx CVE probes |
| File Permissions Modification | T1222 | chattr -ia .ssh commands |
