# 09 — Lessons Learned

> **Status: Deployment phase complete. Analysis phase lessons will be added after May 28, 2026.**
> This document captures what went wrong, what was surprising, what we'd do differently, and defensive recommendations derived from observed attacker behavior.

---

## Deployment Challenges

### Challenge 1 — Ubuntu 24.04 Socket-Activated SSH

**What happened:** On Ubuntu 24.04, SSH is managed by a systemd socket (`ssh.socket`) in addition to the service (`ssh.service`). Modifying `sshd_config` to change the port and restarting `ssh.service` had no effect — the socket continued binding port 22 because `ssh.socket` was still active and socket activation overrides the config file.

**Symptom:** After multiple `systemctl restart ssh` attempts, `ss -tlnp | grep ssh` consistently showed port 22 still bound.

**Fix:**
```bash
systemctl stop ssh.socket
systemctl disable ssh.socket
# Now the service reads sshd_config directly
systemctl restart ssh.service
```

**Lesson:** On Ubuntu 24.04+, always check for socket-activated services when modifying service configuration. `systemctl status ssh.socket` reveals the activation chain. This behavior is specific to Ubuntu 24.04 and does not exist on 22.04 or earlier.

**Documentation added:** Step 3.2 of the deployment guide explicitly includes `systemctl stop/disable ssh.socket` before the port change.

---

### Challenge 2 — Cowrie Docker Volume Mount Path

**What happened:** Cowrie's Docker image stores logs at `/cowrie/cowrie-git/var/log/cowrie`, not the commonly documented `/cowrie/var/log/cowrie`. The initial docker-compose.yml used the wrong path, resulting in logs being written inside the container with no visibility from the host.

**Symptom:** `ls /opt/cowrie/logs/` on the VPS showed an empty directory even after confirmed connections (`docker logs cowrie` showed connection events).

**Debugging process:**
1. Confirmed Cowrie was receiving connections via `docker logs cowrie`
2. Confirmed the volume was mounted with correct permissions (999:999)
3. Used `docker exec` to search for JSON files inside the container — found `ls` unavailable in the minimal image
4. Used Python inside the container to walk the filesystem and find actual log paths
5. Discovered the correct path: `/cowrie/cowrie-git/var/log/cowrie`

**Fix:** Updated docker-compose.yml volume mount to `./logs:/cowrie/cowrie-git/var/log/cowrie`

**Lesson:** Always verify the exact internal paths of Docker containers by inspecting the running container before writing volume mounts. `docker inspect <container> | grep -A 10 "Mounts"` shows the active mounts, but doesn't reveal whether they're targeting the right internal path.

---

### Challenge 3 — WireGuard Asymmetric Routing

**What happened:** After the WireGuard tunnel was established and confirmed active (handshake confirmed, `wg show` showed data transfer), SSH connections from the VPS to Ubuntu Server timed out. `tcpdump` on Ubuntu Server showed SYN packets arriving but replies going out the wrong interface.

**Root cause:** Ubuntu Server has two network interfaces:
- `enp0s1` (192.168.64.x) — default gateway via UTM
- `enp0s2` (192.168.10.4) — VLAN 10 connection to OPNsense

When the VPS (10.10.10.2) sent a SYN packet, it arrived via `enp0s2` (through OPNsense). But Ubuntu Server had no route for `10.10.10.0/30`, so the SYN-ACK reply was sent via the default route (`enp0s1`), which had no path back to the VPS. The VPS received no reply and kept retransmitting SYN.

**Diagnosis via tcpdump:**
```
enp0s2 In  IP 10.10.10.2 > 192.168.10.4: SYN
enp0s1 Out IP 192.168.10.4 > 10.10.10.2: SYN-ACK  ← wrong interface
```

**Fix:** Added static route on Ubuntu Server:
```bash
sudo ip route add 10.10.10.0/30 via 192.168.10.1 dev enp0s2
```
Made permanent in netplan (`/etc/netplan/50-cloud-init.yaml`).

**Lesson:** Any time a host has multiple network interfaces and you're routing traffic through a VPN/tunnel, verify the return path explicitly. The presence of a WireGuard handshake does not guarantee bidirectional TCP connectivity — handshake uses UDP keepalives which don't require symmetric routing. TCP connections do.

---

### Challenge 4 — Windows/WSL Paste Issues in Terminal

**What happened:** Multiple commands failed because content was pasted from the Windows clipboard into an SSH session, and the Windows-style line endings or prompt characters from previous output were included in the pasted text.

**Symptom:** Commands like `cat > file << 'EOF'` failed with syntax errors because the previous terminal prompt (`tyceerickson@TyceErickson:/mnt/c/Users/tycee$`) was pasted as part of the command.

**Lesson:** When using Windows PowerShell + WSL to SSH into a remote server, always type commands manually rather than pasting multi-line blocks, especially when already inside an SSH session. The clipboard may contain residual terminal output.

**Mitigation for future deployments:** Use the DigitalOcean web console for initial setup, then switch to SSH once the Tailscale + key auth path is confirmed. The web console eliminates paste artifacts entirely.

---

### Challenge 5 — DigitalOcean Firewall Not Applied After Rebuild

**What happened:** After restoring the Droplet to base image (to fix accumulated configuration issues), the existing DigitalOcean Cloud Firewall was not automatically re-associated. Port 2222 was not open in the firewall, causing Tailscale-based SSH to fail even after Tailscale was installed on the rebuilt VPS.

**Lesson:** Always verify Cloud Firewall association after any VPS rebuild or restore. Navigate to **Networking → Firewalls** and confirm the Droplet appears under the `cowrie-honeypot` firewall's **Droplets** tab.

---

## What Surprised Us

### Surprise 1 — Speed of Initial Indexing

The honeypot received its first SSH connection within **90 seconds** of ports 22/23 being opened. The attacker was a Go-based automated scanner that logged in with `root/Password1` and ran `uname -s -v -n -r -m` — all within 1.6 seconds.

This demonstrates that NYC1 IP space is under continuous automated scanning by global infrastructure. A naive mental model is "it takes time for attackers to find a new IP" — in reality, the attacker population running internet-wide scanners means any new IP is discovered almost instantly.

**Practical implication:** Any public-facing server without proper hardening is compromised within minutes, not days. The first-credential-success metric for `root/Password1` within 90 seconds of going live reinforces that even moderately common passwords provide essentially no security on internet-exposed SSH.

### Surprise 2 — Geographic Concentration

43% of first-hour traffic originated from Hong Kong, specifically from Alibaba Cloud and similar hosting infrastructure. Germany (Hetzner) was second at 21%.

This is not because Hong Kong or German citizens are attacking the honeypot. It reflects where attackers rent infrastructure: large cloud providers in Asia-Pacific and European regions with cheap VPS pricing and permissive terms of service. The actual human operators may be anywhere in the world.

**Practical implication:** IP-based geo-blocking is security theater. Blocking Hong Kong IPs does nothing if the attacker switches to a Frankfurt VPS.

### Surprise 3 — The Cowrie Fake Shell Fools Automated Tools

Automated scanners that logged in with valid credentials ran their full reconnaissance scripts against the fake shell and received plausible-looking fake output — without detecting they were in a honeypot. The session ended after the script completed normally.

This means Cowrie successfully captures the full behavioral profile of the automated tool, including what commands it runs, in what order, and what it does with the output. The behavioral signature of these scripts is more valuable for detection than the credential pairs themselves.

---

## What We Would Do Differently

### 1. Start With `docker-compose.yml` Volume Path Verification

Before running `docker-compose up`, verify the correct internal log path by running the container temporarily with a shell-accessible entrypoint:
```bash
docker run --rm --entrypoint=/bin/sh cowrie/cowrie:latest -c "find / -name '*.json' 2>/dev/null"
```
Five minutes of pre-verification would have saved an hour of debugging.

### 2. Use a Configuration Management Tool for VPS Setup

The VPS setup involves 30+ commands across 9 phases. Running them interactively is error-prone. A simple Ansible playbook or bash setup script would make the deployment reproducible and auditable. This is a priority for Project 4.

### 3. Set Up Disk Space Monitoring Before Going Live

The disk alert cron was added after deployment. With 1,076 events in the first hour, high-traffic periods could theoretically fill the 25GB disk in under a week. The alert should be configured before the honeypot goes live, not after.

### 4. Deploy a Log Streaming Pipeline Instead of Polling

rsync runs every 15 minutes — that's up to a 15-minute lag between a real attack and its appearance in the SIEM. For a forensic capture project this is acceptable. For Project 4's real-time SOC dashboard, it is not. The next iteration should use Filebeat or Fluentd to stream logs in near-real-time via the WireGuard tunnel.

---

## Defensive Recommendations

Derived from observed attack patterns during the capture period:

### 1. Never Expose SSH Port 22 to the Internet Without fail2ban

The honeypot received thousands of credential attempts per day. Any real server exposed on port 22 without fail2ban (or equivalent) will eventually have a credential pair succeed — either through brute force or because the server uses a common default password.

**Recommendation:** Deploy fail2ban or equivalent with ≤5 attempts before ban, 24-hour ban duration. Or better: disable password authentication entirely and use key-only auth.

### 2. SSH Key Authentication Is Not Optional for Internet-Facing Servers

`root/Password1` succeeded within 90 seconds. This password would be considered "acceptable" by many non-security users. No password is safe against automated brute force at scale. SSH key authentication eliminates this entire attack category.

### 3. Monitor for HASSH Fingerprints, Not Just Source IPs

Source IPs change constantly — attackers rotate through cloud VPS infrastructure. The HASSH value for a specific scanning tool remains constant across IP changes. Building a HASSH watchlist for known malicious scanners provides more durable detection than IP blocklists.

### 4. The First Commands After Login Reveal the Tool

The sequence `uname -s -v -n -r -m` followed by session close in under 2 seconds is the behavioral signature of a specific automated post-exploitation script. Defenders can detect this pattern in their SSH logs even without a honeypot — any legitimate user would take more than 2 seconds to run commands after login.

### 5. Web Vulnerability Scanners Announce Themselves

Scanners like Nuclei, zgrab, and masscan include identifying strings in their User-Agent headers. Logging and analyzing HTTP User-Agent strings provides free scanner identification with no additional tooling.

---

## Open Questions for Future Analysis

1. **What percentage of credential attackers are the same infrastructure?** HASSH fingerprinting may reveal that a small number of tools account for a large percentage of attacks.

2. **Do Dionaea captures correlate with CVE disclosure dates?** If a new SMB vulnerability is disclosed, does exploit traffic spike in the following days?

3. **Are the botnet C2 IPs in the `wget`/`curl` commands from Cowrie sessions already known?** Cross-referencing against threat intelligence feeds (AlienVault OTX, VirusTotal) would validate the data quality.

4. **What is the real dwell time before attackers return to a known-good IP?** If the same ASN keeps appearing in logs over 7 days, it suggests coordinated persistent scanning infrastructure rather than random scanning.
