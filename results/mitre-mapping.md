# MITRE ATT&CK Mapping — Observed Techniques

> Generated from 11,611,908 Wazuh alerts · 6-day honeypot capture · May 21–28, 2026
> Full analysis: `docs/07-mitre-attack-mapping.md`

---

## Quick Reference Table

| ATT&CK ID | Technique | Tactic | Events | Status |
|-----------|-----------|--------|--------|--------|
| T1046 | Network Service Discovery | Reconnaissance | 2,617,958 | ✅ Confirmed |
| T1110.001 | Brute Force: Password Guessing | Credential Access | 873,373 | ✅ Confirmed |
| T1110.003 | Brute Force: Password Spraying | Credential Access | ~150,000 | ✅ Confirmed |
| T1190 | Exploit Public-Facing Application | Initial Access | 6,225 | ✅ Confirmed |
| T1021.004 | Remote Services: SSH | Lateral Movement | 5,358 | ✅ Confirmed |
| T1059 | Command and Scripting Interpreter | Execution | 501,689 | ✅ Confirmed |
| T1082 | System Information Discovery | Discovery | ~200,000 | ✅ Confirmed |
| T1105 | Ingress Tool Transfer | Command & Control | 165,580 | ✅ Confirmed |
| T1098.004 | SSH Authorized Keys | Persistence | 149,348 | ✅ Confirmed |
| T1222 | File Permissions Modification | Defense Evasion | 149,509 | ✅ Confirmed |
| T1053 | Scheduled Task/Job | Persistence | 1,805 | ✅ Confirmed |
| T1070 | Indicator Removal | Defense Evasion | 1,821 | ✅ Confirmed |
| T1078 | Valid Accounts | Defense Evasion | 5,358 | ✅ Confirmed |
| T1552.001 | Credentials in Files | Credential Access | 1,127 | ✅ Confirmed |
| T1083 | File and Directory Discovery | Discovery | 13 | ✅ Confirmed |
| T1210 | Exploitation of Remote Services | Lateral Movement | 0 | ❌ Not observed |
| T1505.003 | Web Shell | Persistence | 0 confirmed | ⚠️ Probed |

---

## Top 5 Techniques by Volume

### 1. T1046 — Network Service Discovery (2,617,958 events)
Every session begins with a connection probe. The VPS received 2.6 million SSH connection attempts — all classified as network service discovery before any credential attempt.

### 2. T1110.001 — Brute Force: Password Guessing (873,373 events)
873,373 failed credential attempts over 6 days. Top password: `3245gs5662d34` (161,992 attempts) — a botnet-specific token, not a common password.

### 3. T1059 — Command and Scripting Interpreter (501,689 events)
501,689 commands executed in the fake shell after login. Dominated by automated scripts, not human operators.

### 4. T1098.004 — SSH Authorized Keys (149,348 events)
Single most dangerous technique observed. A coordinated campaign injected an RSA backdoor key (`mdrfckr`) into `~/.ssh/authorized_keys` 149,348 times.

### 5. T1105 — Ingress Tool Transfer (165,580 events)
165,580 malware download attempts. One payload hash (`a8460f44...`) was downloaded 149,364 times — the same binary delivered by the SSH key implant campaign.

---

## Key Evidence: SSH Key Implant Campaign

The most significant finding — two commands executed in sequence 149,000+ times:

```bash
# Step 1: Remove file protection (T1222)
cd ~; chattr -ia .ssh; lockr -ia .ssh

# Step 2: Install backdoor key (T1098.004)
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAAB...mdrfckr" >> .ssh/authorized_keys
```

Campaign identifier: RSA key comment `mdrfckr` — tracked across multiple honeypot networks globally.

---

## Web Attack CVE Evidence (T1190)

| CVE | Description | Probes |
|-----|-------------|--------|
| CVE-2017-9841 | PHPUnit RCE | 450 |
| CVE-2023-1389 | OpenWRT Luci RCE | 55 |
| CVE-2021-36260 | Hikvision Camera RCE | 28 |

All three CVEs received probes within hours of the IP going live — confirming fully automated CVE scanning infrastructure operating continuously on the internet.

---

*Full technique details with log evidence: `docs/07-mitre-attack-mapping.md`*
*Raw data: `results/attack-analysis.md`, `results/ai-context.md`*
