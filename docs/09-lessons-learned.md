# 09 — Lessons Learned

> **Status: Complete — Written after 6-day capture period (May 21–28, 2026).**
> Documents technical challenges, operational surprises, and defensive insights gained from running an internet-facing honeypot.

---

## Overview

This document captures what went wrong, what was surprising, and what this project teaches about real-world attack behavior and honeypot operations. It is intended as an honest post-mortem, not a polished summary.

---

## Deployment Lessons

### Lesson 1 — Ubuntu 24.04 SSH Socket Activation

**What happened:** After changing the SSH port from 22 to 2222 on the VPS, SSH connections were refused. The standard `sshd_config` change didn't work.

**Root cause:** Ubuntu 24.04 uses socket-activated SSH (`ssh.socket`) via systemd. The socket unit overrides `sshd_config` port settings. The socket must be disabled before port changes take effect.

**Fix:**
```bash
systemctl disable ssh.socket
systemctl stop ssh.socket
systemctl restart sshd
```

**Lesson:** Always check for systemd socket units before modifying service ports on Ubuntu 24.04+. This is a known gotcha that affects any service using socket activation.

---

### Lesson 2 — Cowrie Docker Volume Path

**What happened:** Cowrie logs weren't appearing in the expected output directory.

**Root cause:** The documented Cowrie Docker volume path (`/cowrie/var/log/cowrie`) is incorrect for the `cowrie/cowrie:latest` image. The actual path is `/cowrie/cowrie-git/var/log/cowrie`.

**Fix:** Update `docker-compose.yml` volume mount:
```yaml
volumes:
  - ./logs:/cowrie/cowrie-git/var/log/cowrie
```

**Lesson:** Always verify Docker volume paths against the actual container filesystem, not just documentation.

---

### Lesson 3 — WireGuard Asymmetric Routing

**What happened:** WireGuard tunnel was showing successful handshakes but TCP connections between VPS and Ubuntu Server were failing intermittently.

**Root cause:** Asymmetric routing — packets from the VPS arrived via WireGuard but replies were routing out through the default interface instead of back through the tunnel. WireGuard handshake succeeding does not mean TCP traffic is working.

**Fix:** Add static route on Ubuntu Server via netplan:
```yaml
routes:
  - to: 10.10.10.0/30
    via: 192.168.10.1
    metric: 100
```

**Lesson:** WireGuard handshake success ≠ TCP connectivity. Always test actual data flow (rsync a file) immediately after tunnel setup, not just ping.

---

### Lesson 4 — API Key Hygiene

**What happened:** The MaxMind GeoLite2 license key was accidentally committed to the GitHub repository in a configuration file and became publicly visible.

**Root cause:** License key was hardcoded in a script during initial development rather than being stored as an environment variable.

**Fix:** Immediately rotated the license key via MaxMind account portal. Added `*.key`, `.env` to `.gitignore`. Moved key to environment variable: `export MAXMIND_LICENSE_KEY=...`

**Lesson:** Treat all API keys as compromised immediately upon public exposure, even briefly. Use environment variables or a secrets manager — never hardcode credentials in files that will be committed. The `git log` permanently records the key even after deletion from the current branch.

---

## Operational Lessons

### Lesson 5 — OPNsense 26.1 + Suricata VLAN Bug

**What happened:** Suricata IDS on OPNsense 26.1 failed to capture packets from VLAN interfaces. Packet captures showed no traffic on VLAN 10 despite active honeypot activity.

**Root cause:** Known compatibility bug between OPNsense 26.1's network stack and Suricata 8.0.3's VLAN PCAP implementation. The bug was confirmed in OPNsense forums but not yet patched.

**Fix:** Moved Suricata to offline analysis mode on Ubuntu Server — capture packets with tcpdump, analyze offline rather than inline.

**Lesson:** Check OPNsense release notes and community forums before upgrading in a production lab. Major version upgrades (25.x → 26.x) frequently break IDS/IPS integrations.

---

### Lesson 6 — Dionaea Disk-Full Incident

**What happened:** On May 25–26, 2026, Dionaea's verbose debug logging filled the 25GB VPS disk, causing Cowrie to stop writing logs for approximately 24–48 hours. The dated log files for May 26–27 show 0 bytes in the Cowrie log rotation.

**Root cause:** Dionaea's default log level is `DEBUG`, which logs every packet parsing operation at the scapy level. One attacker connecting to port 1433 (MSSQL) triggered millions of repeated TDS header parsing messages in a tight loop. The result: 11.4 million log lines (1.5GB) from a single attacker connection, zero meaningful incident data.

**Timeline:**
- May 25 evening: Dionaea log growth accelerates
- May 26 00:00: VPS disk reaches 100% capacity
- May 26 00:00–May 27 00:00: Cowrie cannot write logs, 24+ hours of data lost
- May 27: Disk manually cleared, logging resumed

**Estimated data loss:** 1–2 days of Cowrie SSH logs. The data gap is visible in the OpenSearch index — May 26 shows significantly reduced volume (1,742,714 vs 2.6M+ on surrounding days).

**Fix:**
1. Add Dionaea log level configuration:
```
[logging]
default = warning
```
2. Add disk space monitoring alert:
```bash
# Add to crontab
*/15 * * * * df / | awk 'NR==2{if($5+0>80) print "DISK ALERT: "$5" used"}' | mail -s "VPS Disk Alert" admin@example.com
```
3. Add Dionaea log rotation:
```
/opt/cowrie/dionaea-logs/dionaea.log {
    daily
    rotate 3
    compress
    size 100M
    missingok
}
```

**Lesson:** Configure log verbosity for every service before deployment. Debug-level logging from any service can fill disk surprisingly fast — Dionaea generates ~1GB/hour at debug level under active attack. Disk monitoring should be configured before the honeypot goes live, not after.

---

### Lesson 7 — rsync Log Rotation Gap

**What happened:** The rsync pipeline was syncing `cowrie.json` every 15 minutes, but log rotation on the VPS creates dated backup files (`cowrie.json.2026-05-21`, etc.). The rsync only copied the current file, not the rotated archives.

**Root cause:** rsync configured to sync only the active log file, not the entire log directory.

**Impact:** The Ubuntu Server enriched log only contained recent data (whatever was in the current `cowrie.json`), not the full 7-day dataset. The full historical data was on the VPS in rotated files.

**Fix:** Update rsync to include all log files:
```bash
rsync -avz --include="cowrie.json*" --include="*.gz" /opt/cowrie/logs/ ubuntu@homeserver:/opt/cowrie-logs/
```

**Lesson:** Always test the full log pipeline end-to-end, including log rotation behavior, before relying on it for data collection.

---

## Analysis Lessons

### Lesson 8 — OpenSearch as the Source of Truth

**What happened:** We initially tried to analyze data from the flat JSON files synced to Ubuntu Server, but discovered these were partial due to the rsync gap (Lesson 7). The complete dataset was in OpenSearch/Wazuh, which had been ingesting directly from the VPS.

**Key insight:** OpenSearch was the only system with the complete 7-day dataset. The 11,611,908 events in OpenSearch vs ~209,919 events in the flat files reflects the rsync pipeline gap.

**Fix:** Export directly from OpenSearch using the scroll API:
```python
curl -k -u admin:password "https://localhost:9200/wazuh-alerts-4.x-*/_search?scroll=5m" \
  -d '{"size": 10000, "query": {"match_all": {}}}'
```

**Lesson:** When running multiple data collection pipelines (rsync + Wazuh), always verify which system has the authoritative complete dataset before running final analysis.

---

### Lesson 9 — HASSH Fingerprinting Defeats Version String Spoofing

**What happened:** During analysis, we noticed that the SSH client version string reported by Paramiko sessions (`SSH-2.0-libssh_0.9.6`) didn't match the HASSH fingerprint (`f555226df1963d1d3c09daf865abdc9a` = Paramiko 2.x).

**Key insight:** Attackers were spoofing their SSH client version string to appear as `libssh_0.9.6` — a different library — while the HASSH fingerprint revealed the actual underlying library. This is an active evasion technique that defeats version-string-based detection but is completely transparent to HASSH analysis.

**Lesson:** HASSH fingerprinting is significantly more reliable than SSH client version strings for tool identification. Version strings are self-reported and trivially spoofed; HASSH is derived from the cryptographic algorithm negotiation which is much harder to fake without breaking the connection.

---

### Lesson 10 — Dionaea Provided Zero Useful Data

**What happened:** Despite 11.4 million Dionaea log lines, there were zero meaningful attack incidents, zero malware captures, and zero exploit attempts in the structured data.

**Root cause:** The entire Dionaea log was debug output from a single attacker connecting to port 1433. The ports Dionaea covers (SMB 445, FTP 21, MSSQL 1433, MySQL 3306) received far less targeted attack traffic than SSH (port 22) during this capture window.

**Key insight:** SSH brute force remains the overwhelmingly dominant attack vector against Linux cloud infrastructure. IoT/Windows-targeting services (SMB, MSSQL) receive significantly less automated attack traffic on a fresh DigitalOcean IP compared to SSH.

**Lesson:** For a Linux cloud honeypot, SSH is the primary attack surface worth instrumenting. Dionaea adds value for Windows-targeting attack research but requires careful log level configuration and is not a high-value addition to a Linux-focused deployment.

---

## What Was Surprising

1. **Speed of discovery:** The honeypot received its first credential attempt within 90 seconds of going live. This was faster than expected — Shodan/Censys indexing typically takes hours, suggesting some scanning infrastructure continuously monitors new IP assignments in real time.

2. **Campaign concentration:** We expected diverse attack traffic. Instead, a single botnet campaign (`3245gs5662d34` credentials + `mdrfckr` RSA key) accounted for 37% of all credential traffic and 30% of all post-login commands. Internet-wide attacks are far more coordinated than expected.

3. **Tool concentration:** Two tool families (Paramiko 2.x and a Go SSH scanner) accounted for 1.18 million sessions — 45% of all traffic. Internet-wide SSH scanning is dominated by a surprisingly small ecosystem of automated tools.

4. **Post-quantum attack tools:** 62,126 sessions used OpenSSH with post-quantum key exchange algorithms (mlkem768x25519, mlkem768nistp256). Attack infrastructure is keeping pace with the latest cryptographic standards — attackers upgrade their tools alongside defenders.

5. **CVE longevity:** CVE-2017-9841 (PHPUnit RCE, disclosed 2017) received 450 exploit attempts in 2026 — 9 years after disclosure. Unpatched vulnerabilities face ongoing active exploitation indefinitely, not just in the months after disclosure.

6. **Microsoft Azure as attack infrastructure:** Four of the top 10 nginx attacker IPs were Microsoft Azure addresses (20.x.x.x range). Major cloud providers are extensively abused for attack infrastructure, making IP-based blocking ineffective.

---

## Defensive Recommendations

Based on 11,611,908 events over 6 days:

| Priority | Action | Rationale |
|----------|--------|-----------|
| 1 | Disable SSH password authentication | Eliminates 873,373 brute force attempts entirely |
| 2 | Configure fail2ban (3 failures / 24h ban) | Stops all observed brute force patterns |
| 3 | Block AS197328 (Pfcloud UG) | Eliminates ~20% of all attack traffic |
| 4 | Alert on HASSH `f555226df1963d1d3c09daf865abdc9a` | Detects 55% of SSH attack traffic |
| 5 | Monitor for `chattr -ia .ssh` execution | Detects SSH key implant campaign immediately |
| 6 | Patch CVE-2023-1389 and CVE-2021-36260 | Closes actively exploited vulnerabilities |
| 7 | Remove PHPUnit from production | CVE-2017-9841 still actively exploited 9 years later |
| 8 | Configure Dionaea log level to WARNING | Prevents disk-full incidents from debug logging |
| 9 | Add disk monitoring to all internet-facing systems | Early warning before service interruption |
| 10 | Use HASSH over version strings for SSH detection | Version strings are spoofed; HASSH is not |
