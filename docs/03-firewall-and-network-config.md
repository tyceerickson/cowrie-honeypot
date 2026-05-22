# 03 — Firewall & Network Configuration

All firewall rules documented with policy rationale. Follows the same format as Project 1's `04-firewall-rules.md`.

---

## DigitalOcean Cloud Firewall — `cowrie-honeypot`

The DigitalOcean Cloud Firewall is enforced at the hypervisor level before traffic reaches the VPS. It is the outermost security boundary.

### Inbound Rules

| # | Protocol | Port | Source | Purpose | Rationale |
|---|----------|------|--------|---------|-----------|
| 1 | TCP | 22 | All IPv4/IPv6 | Cowrie SSH honeypot | Open to world intentionally — this is the primary attack surface. Cowrie receives all connections. |
| 2 | TCP | 23 | All IPv4/IPv6 | Cowrie Telnet honeypot | Open to world intentionally — Telnet brute force is a distinct attack category from SSH. |
| 3 | TCP | 80 | All IPv4/IPv6 | nginx HTTP honeypot | Open to world — web scanners and CVE probes require HTTP access. |
| 4 | TCP | 443 | All IPv4/IPv6 | nginx HTTPS honeypot | Open to world — HTTPS scanning is a separate category from HTTP. |
| 5 | TCP | 21 | All IPv4/IPv6 | Dionaea FTP honeypot | Open to world — FTP attracts file upload malware delivery attempts. |
| 6 | TCP | 445 | All IPv4/IPv6 | Dionaea SMB honeypot | Open to world — SMB is the highest-value port for worm/ransomware capture (EternalBlue, WannaCry). |
| 7 | TCP | 1433 | All IPv4/IPv6 | Dionaea MSSQL honeypot | Open to world — MSSQL credential attacks are a distinct attack category. |
| 8 | TCP | 3306 | All IPv4/IPv6 | Dionaea MySQL honeypot | Open to world — MySQL credential stuffing is common and generates distinct log patterns. |
| 9 | TCP | 2222 | `100.72.171.104` only | Real SSH management | **Tailscale IP only.** Allows management access from Alienware without exposing management to attackers. Port 22 is entirely consumed by Cowrie. |
| 10 | UDP | 51820 | All IPv4/IPv6 | WireGuard tunnel | Open to world — WireGuard validates by cryptographic public key, making IP restriction redundant. All unauthorized connection attempts are silently dropped by the WireGuard protocol. |

### Outbound Rules

| Protocol | Port | Destination | Rationale |
|----------|------|-------------|-----------|
| ICMP | All | All IPv4/IPv6 | Required for network diagnostics |
| TCP | All | All IPv4/IPv6 | Required for package updates, WireGuard log forwarding, Tailscale |
| UDP | All | All IPv4/IPv6 | Required for WireGuard (UDP 51820 to OPNsense WAN) |

**Note on outbound rule hardening:** The iptables rule `iptables -I OUTPUT -m owner --uid-owner 999 -j DROP` blocks any outbound connections initiated by Cowrie's UID (999) at the OS level. This means even if an attacker identifies the fake shell and attempts to initiate outbound connections, the iptables rule drops them before they leave the VPS. This is defense-in-depth operating below the DigitalOcean firewall layer.

---

## OPNsense WireGuard Configuration

### Instance: `wg-honeypot`

| Field | Value |
|-------|-------|
| Name | `wg-honeypot` |
| Instance | wg0 |
| Listen Port | 51820 |
| Tunnel Address | `10.10.10.1/30` |
| Disable Routes | ☐ unchecked |
| Peer | `ubuntu-home-server-droplet` |

### Peer: `ubuntu-home-server-droplet`

| Field | Value |
|-------|-------|
| Name | `ubuntu-home-server-droplet` |
| Allowed IPs | `10.10.10.2/32` |
| Endpoint address | `174.138.35.11` |
| Endpoint port | `51820` |
| Keepalive interval | `25` |
| Instances | `wg-honeypot` |

### WireGuard Subnet

| Address | Host |
|---------|------|
| `10.10.10.0/30` | Network |
| `10.10.10.1` | OPNsense WireGuard interface |
| `10.10.10.2` | VPS WireGuard interface |
| `10.10.10.3` | Broadcast |

---

## OPNsense Interface: HoneypotOPT6

The WireGuard interface is assigned as `HoneypotOPT6` (opt6) in OPNsense.

| Field | Value |
|-------|-------|
| Identifier | opt6 |
| Device | wg0 |
| Description | HoneypotOPT6 |
| Enable Interface | ✅ |
| IPv4 Configuration Type | None (WireGuard manages IP) |
| Block Private Networks | ☐ |
| Block Bogon Networks | ☐ |

---

## OPNsense Firewall Rules — HoneypotOPT6

### Rule 1 — Allow VPS to reach VLAN 10

| Field | Value |
|-------|-------|
| Action | Pass |
| Interface | HoneypotOPT6 (OPT6) |
| Direction | in |
| Protocol | Any |
| Source | `10.10.10.0/30` |
| Destination | `192.168.10.0/24` |
| Description | `Allow VPS honeypot to reach VLAN 10 for log forwarding` |

**Policy rationale:** This rule permits one specific traffic flow: the VPS (10.10.10.0/30) sending rsync/SSH log forwarding traffic to Ubuntu Server (192.168.10.0/24). It does not permit the VPS to reach any other VLAN (20/30/40), any management interfaces, or the OPNsense GUI. The scope is deliberately narrow, only the log forwarding destination is reachable.

**Why this is safe:** The VPS is a hardened container host. The only services running are Cowrie (UID 999, outbound blocked by iptables), nginx, Dionaea, and WireGuard. The WireGuard tunnel authenticates by public key, no other device on the internet can inject traffic through this rule by spoofing the VPS address.

---

## Ubuntu Server Routing

Ubuntu Server has two network interfaces:

| Interface | Network | IP | Role |
|-----------|---------|-----|------|
| enp0s1 | 192.168.64.0/24 | 192.168.64.2 | Default gateway (UTM internal) |
| enp0s2 | 192.168.10.0/24 | 192.168.10.4 | Lab management network (VLAN 10) |

### Static Routes (persistent via netplan)

| Route | Via | Interface | Purpose |
|-------|-----|-----------|---------|
| `10.10.10.0/30` | `192.168.10.1` | enp0s2 | Return path for WireGuard tunnel replies |
| `192.168.0.0/16` | `192.168.10.1` | enp0s2 | All VLAN routing via OPNsense |

**Why the 10.10.10.0/30 route is required:** Without this route, Ubuntu Server sends reply packets to the VPS (10.10.10.2) via the default gateway (enp0s1 → 192.168.64.1), which has no route to the WireGuard subnet. The VPS sends SYN packets through the tunnel, OPNsense forwards them to Ubuntu Server via enp0s2, but Ubuntu Server replies via enp0s1, causing asymmetric routing that prevents the TCP handshake from completing. This static route corrects the return path.

### Netplan Configuration (`/etc/netplan/50-cloud-init.yaml`)

```yaml
network:
  version: 2
  ethernets:
    enp0s1:
      dhcp4: true
      dhcp4-overrides:
         route-metric: 100
    enp0s2:
      dhcp4: false
      addresses:
        - 192.168.10.4/24
      routes:
        - to: 10.10.10.0/30
          via: 192.168.10.1
        - to: 192.168.0.0/16
          via: 192.168.10.1
```

---

## VPS WireGuard Configuration Template

The actual VPS WireGuard config (`/etc/wireguard/wg0.conf`) follows this structure. Private key is redacted.

```ini
[Interface]
PrivateKey = <REDACTED>
Address = 10.10.10.2/30
ListenPort = 51820

[Peer]
# OPNsense wg-honeypot instance
PublicKey = OWvU3nYRQLsWUljyl4t25rmw0ZvYqzgTtjAqU6RV1C4=
AllowedIPs = 10.10.10.1/32, 192.168.10.0/24
PersistentKeepalive = 25
```

**AllowedIPs explanation:** `10.10.10.1/32` routes tunnel keepalive and control traffic to OPNsense's tunnel IP. `192.168.10.0/24` routes log forwarding traffic to the entire VLAN 10 subnet, specifically Ubuntu Server at 192.168.10.4. Any traffic the VPS sends destined for 192.168.10.x is automatically sent through the encrypted WireGuard tunnel.

---

## VPS Hardening Summary

| Control | Configuration | Purpose |
|---------|--------------|---------|
| SSH port | 2222 (moved from 22) | Port 22 fully consumed by Cowrie; prevents management lockout |
| SSH auth | Key-only (PasswordAuthentication no) | Eliminates password brute force on management port |
| SSH access | Tailscale IP only (via Cloud Firewall) | Management access restricted to authenticated Tailscale network |
| fail2ban | Port 2222, 3 attempts, 24h ban | Protects management SSH from automated scanning |
| iptables | UID 999 outbound blocked | Cowrie cannot initiate outbound connections even if compromised |
| Unattended upgrades | Enabled | OS security patches applied automatically during capture week |
| Docker restart policy | `unless-stopped` | All honeypot containers restart automatically after VPS reboot |
| Tailscale | Installed, authenticated | Permanent stable management access independent of IP changes |
