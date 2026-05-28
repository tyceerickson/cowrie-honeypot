# 07 — MITRE ATT&CK Mapping

> **Status: Complete — Updated with real event counts from 11.6M event dataset.**
> Techniques mapped to observed behaviors from 6-day honeypot capture (May 21–28, 2026).

---

## Overview

This document maps observed attacker behaviors to the MITRE ATT&CK Framework. Each technique includes the ATT&CK technique ID, observed behavior, exact log evidence, real event counts, and Wazuh detection opportunity.

The honeypot captures behaviors across four ATT&CK tactics: **Reconnaissance**, **Initial Access**, **Execution**, and **Persistence**. This is expected — a honeypot by definition captures only the earliest phases of an attack chain.

---

## Tactic: Reconnaissance

### T1046 — Network Service Discovery

**Observed:** Automated scanners connected to port 22, performed SSH version negotiation, and recorded the server banner without attempting credentials. Port 22 was targeted within 90 seconds of the IP going live.

**Event count:** 2,617,958 `cowrie.session.connect` events

**Log evidence:**
```json
{
  "eventid": "cowrie.session.connect",
  "src_ip": "152.32.187.177",
  "src_port": 52341,
  "protocol": "ssh",
  "timestamp": "2026-05-23T22:01:35.376890Z"
}
```

**Detection opportunity:** Alert on `cowrie.session.connect` events from IPs with >5 connections in 60 seconds. The HASSH fingerprint from `cowrie.client.kex` fires before any login attempt and identifies the scanning tool immediately.

---

## Tactic: Initial Access

### T1110.001 — Brute Force: Password Guessing

**Observed:** Automated tools attempted sequential credential pairs from pre-built dictionaries. The most common pattern: `root` username with password list iteration. 873,373 failed login attempts over 6 days.

**Event count:** 873,373 `cowrie.login.failed` events

**Log evidence:**
```json
{
  "eventid": "cowrie.login.failed",
  "username": "root",
  "password": "123456",
  "src_ip": "45.156.87.254",
  "session": "59501bce750e",
  "timestamp": "2026-05-24T14:22:11.800000Z"
}
```

**Top credential pairs observed:**

| Username | Password | Attempts |
|----------|----------|---------|
| root | 3245gs5662d34 | 161,992 |
| 345gs5662d34 | 345gs5662d34 | 161,584 |
| admin | admin | 6,747 |
| root | admin | 3,655 |
| root | root | 2,936 |

**Detection opportunity:** Alert on >5 `cowrie.login.failed` events from the same source IP within 60 seconds. The `3245gs5662d34` credential pair is a known botnet signature — block on first attempt.

---

### T1110.003 — Brute Force: Password Spraying

**Observed:** Some automated tools cycled through username lists with a fixed small set of passwords. Sessions with >10 unique usernames but <5 unique passwords.

**Event count:** Subset of 873,373 failed login events — ~15-20% of sessions showed spraying pattern

**Top sprayed usernames observed:** root, admin, user, ubuntu, test, deploy, postgres, sol, minecraft, steam, oracle, pi, mysql, guest, debian, frappe, git, solana, testuser, claude

**Detection opportunity:** Alert when a single session attempts >10 unique usernames but <5 unique passwords.

---

### T1190 — Exploit Public-Facing Application

**Observed:** Automated CVE scanners probed the nginx web honeypot for known vulnerabilities within hours of IP assignment.

**Event count:** 6,225 nginx requests; 1,558 high-value exploit attempts

**Log evidence (CVE-2023-1389 OpenWRT RCE):**
```
45.139.122.80 - - [2026-05-23T14:22:11] "GET /cgi-bin/luci/;stok=/locale HTTP/1.1" 200 -
```

**Log evidence (PHPUnit RCE CVE-2017-9841):**
```
77.68.25.99 - - [2026-05-24T09:15:44] "POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 200 -
```

**Log evidence (Hikvision CVE-2021-36260):**
```
185.177.72.24 - - [2026-05-23T18:44:12] "GET /SDK/webLanguage HTTP/1.1" 200 -
```

**CVE breakdown:**

| CVE | Description | Requests |
|-----|-------------|---------|
| CVE-2017-9841 | PHPUnit Remote Code Execution | 450 |
| CVE-2023-1389 | OpenWRT Luci RCE | 55 |
| CVE-2021-36260 | Hikvision Camera RCE | 28 |
| None (path traversal) | `/cgi-bin/.%2e/.%2e/bin/sh` | 13 |
| None (`.env` exposure) | Environment file credential theft | 1,127 |

**Detection opportunity:** Alert on nginx requests containing `.env`, `/vendor/phpunit`, `/cgi-bin/luci`, `/SDK/webLanguage`, `${jndi:`, `..%2f`.

---

### T1021.004 — Remote Services: SSH

**Observed:** Following `cowrie.login.success`, attacker gains access to the fake shell. 5,358 successful logins recorded.

**Event count:** 5,358 `cowrie.login.success` events

**Log evidence:**
```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "3245gs5662d34",
  "src_ip": "103.133.160.33",
  "session": "c185b98aafc3",
  "timestamp": "2026-05-22T00:16:15.673366Z"
}
```

**Detection opportunity:** Every `cowrie.login.success` is malicious by definition in a honeypot. Alert on any single event — severity CRITICAL.

---

## Tactic: Execution

### T1059 — Command and Scripting Interpreter

**Observed:** 501,689 commands executed in fake shell across 5,358 post-login sessions. Attackers ran automated scripts immediately upon login.

**Event count:** 501,689 `cowrie.command.input` events

**Log evidence:**
```json
{
  "eventid": "cowrie.command.input",
  "input": "uname -s -v -n -r -m",
  "src_ip": "47.82.102.10",
  "session": "59501bce750e",
  "timestamp": "2026-05-21T18:13:44.583410Z"
}
```

**Detection opportunity:** Alert on any `cowrie.command.input` event — every command in a honeypot shell is malicious. High-value specific alerts: `wget`, `curl`, `chmod +x`, `crontab`, `rm -rf`.

---

### T1082 — System Information Discovery

**Observed:** System enumeration commands ran in nearly every post-login session. `uname -s -v -n -r -m` was the single most common command, executed 113,080 times — a scripted recon sequence running automatically on login.

**Event count:** ~200,000+ system discovery commands across uname variants, whoami, cpuinfo queries

**Top system discovery commands:**

| Command | Executions |
|---------|-----------|
| `uname -s -v -n -r -m` | 113,080 |
| `uname -a` | 2,073 |
| `whoami` | 2,034 |
| `uname -m` | 1,945 |
| `cat /proc/cpuinfo \| grep name \| wc -l` | 1,901 |
| `lscpu \| grep Model` | 1,804 |
| `w` | 1,806 |
| `top` | 1,805 |

**Detection opportunity:** The combination of `uname` + `cpuinfo` in the same session within 30 seconds is a near-certain indicator of automated post-exploitation recon.

---

### T1105 — Ingress Tool Transfer

**Observed:** 165,580 malware download events. After gaining shell access, attackers attempted to download payloads from C2 infrastructure. Cowrie logs the download command and capture hash.

**Event count:** 165,580 `cowrie.session.file_download` events

**Top download hashes (C2 payloads):**

| Cowrie Capture Hash | Count |
|---------------------|-------|
| `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | 149,364 |
| `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` | 1,826 |
| `e7d3456c307053b17b8ad52d390634d129a4d1165439ffa412f26d173b29d565` | 43 |
| `6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e` | 10 |

The dominant payload (`a8460f44...`) was downloaded 149,364 times — the same malware binary delivered by the SSH key implant campaign. These hashes can be submitted to VirusTotal for malware family identification.

**Detection opportunity:** Alert on `cowrie.session.file_download` events. Download hashes are direct threat intelligence for blocklisting.

---

## Tactic: Persistence

### T1098.004 — Account Manipulation: SSH Authorized Keys

**Observed:** The dominant post-login campaign. 149,348 executions of a two-step sequence:
1. `chattr -ia .ssh` — removes write protection from `.ssh` directory
2. Injects attacker RSA public key into `~/.ssh/authorized_keys`

The RSA key comment `mdrfckr` identifies this as a tracked campaign with documented activity across global honeypot networks.

**Event count:** 149,348 `cowrie.command.input` events matching this pattern

**Log evidence:**
```json
{
  "eventid": "cowrie.command.input",
  "input": "cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O... mdrfckr\" >> .ssh/authorized_keys",
  "session": "c185b98aafc3",
  "timestamp": "2026-05-22T00:16:22.441366Z"
}
```

**Detection opportunity:** Alert on `cowrie.command.input` containing `authorized_keys`. Severity: CRITICAL. This is the highest-value detection in the entire dataset.

---

### T1222 — File and Directory Permissions Modification

**Observed:** `chattr -ia .ssh` executed 149,509 times — always as the first step before the SSH key implant. Removes the immutable (`-i`) and append-only (`-a`) file attributes from the `.ssh` directory to allow overwriting authorized keys.

**Event count:** 149,509 `cowrie.command.input` events

**Detection opportunity:** Alert on `cowrie.command.input` containing `chattr`. Combined with subsequent `authorized_keys` command = confirmed key implant attempt.

---

### T1053 — Scheduled Task/Job

**Observed:** `crontab -l` executed 1,805 times — part of the cryptominer recon script that checks system resources before deploying a miner.

**Event count:** 1,805 `cowrie.command.input` events with `crontab`

**Detection opportunity:** Alert on `cowrie.command.input` containing `crontab`.

---

### T1070 — Indicator Removal

**Observed:** Cleanup scripts deleting themselves from `/tmp/` after execution — anti-forensic behavior indicating attacker awareness of log analysis.

**Event count:** 1,821 `cowrie.command.input` events

**Log evidence:**
```json
{
  "eventid": "cowrie.command.input",
  "input": "rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh",
  "session": "d8f92c1e3ab4",
  "timestamp": "2026-05-24T09:22:15.124566Z"
}
```

---

### T1552.001 — Credentials in Files

**Observed:** 1,127 requests to `/.env` and variants (`/.env.production`, `/.env.local`) — automated scanners seeking database passwords, API keys, and application secrets stored in environment files.

**Event count:** 1,127 nginx access log entries

**Detection opportunity:** Alert on nginx requests to `/.env`, `/.env.production`, `/.env.local`, `/.env.example`.

---

## Complete Technique Reference

| ATT&CK ID | Technique | Tactic | Events | Status |
|-----------|-----------|--------|--------|--------|
| T1046 | Network Service Discovery | Reconnaissance | 2,617,958 sessions | ✅ Confirmed |
| T1110.001 | Brute Force: Password Guessing | Credential Access | 873,373 events | ✅ Confirmed |
| T1110.003 | Brute Force: Password Spraying | Credential Access | ~150,000 events | ✅ Confirmed |
| T1190 | Exploit Public-Facing Application | Initial Access | 6,225 nginx requests | ✅ Confirmed |
| T1021.004 | Remote Services: SSH | Lateral Movement | 5,358 events | ✅ Confirmed |
| T1059 | Command and Scripting Interpreter | Execution | 501,689 events | ✅ Confirmed |
| T1082 | System Information Discovery | Discovery | ~200,000 events | ✅ Confirmed |
| T1105 | Ingress Tool Transfer | Command & Control | 165,580 events | ✅ Confirmed |
| T1098.004 | SSH Authorized Keys | Persistence | 149,348 events | ✅ Confirmed |
| T1222 | File Permissions Modification | Defense Evasion | 149,509 events | ✅ Confirmed |
| T1053 | Scheduled Task/Job | Persistence | 1,805 events | ✅ Confirmed |
| T1070 | Indicator Removal | Defense Evasion | 1,821 events | ✅ Confirmed |
| T1078 | Valid Accounts | Defense Evasion | 5,358 events | ✅ Confirmed |
| T1552.001 | Credentials in Files | Credential Access | 1,127 events | ✅ Confirmed |
| T1083 | File and Directory Discovery | Discovery | 13 events | ✅ Confirmed |
| T1210 | Exploitation of Remote Services | Lateral Movement | 0 events | ❌ Not observed (Dionaea) |
| T1505.003 | Web Shell | Persistence | 0 confirmed | ⚠️ Probed, not confirmed |

---

## Wazuh Rule Priority Matrix

| Priority | Rule | Data Source | Threshold | Rule ID |
|----------|------|-------------|-----------|---------|
| CRITICAL | Successful honeypot login | Cowrie login.success | Any single event | 100103 |
| CRITICAL | SSH key implant attempt | Cowrie command.input | `authorized_keys` in input | 100105 |
| HIGH | SSH brute force | Cowrie login.failed | >5 failures/60s same IP | 100102 |
| HIGH | Malware download attempt | Cowrie file_download | Any single event | 100106 |
| HIGH | Password change attempt | Cowrie command.input | `chpasswd` or `passwd` | 100107 |
| HIGH | File permissions modification | Cowrie command.input | `chattr` in input | — |
| MEDIUM | System enumeration | Cowrie command.input | `uname` or `cpuinfo` | — |
| MEDIUM | CVE probe (nginx) | nginx access | `/vendor/phpunit`, `/cgi-bin/luci`, `/SDK/webLanguage` | — |
| MEDIUM | Environment file probe | nginx access | `/.env` path | — |
| MEDIUM | HASSH fingerprint logged | Cowrie client.kex | Known scanner HASSH | 100109 |
| LOW | New SSH connection | Cowrie session.connect | Any single event | 100101 |
