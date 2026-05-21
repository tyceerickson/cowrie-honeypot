# 02 — Deployment Guide

Complete step-by-step deployment procedure for the internet-facing honeypot. All commands shown are the exact commands run during deployment with verified outputs documented.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| DigitalOcean account | Free tier + $6/month Droplet |
| OPNsense firewall | WireGuard plugin installed (`os-wireguard`) |
| Ubuntu Server | 192.168.10.4 on VLAN 10, accessible from home lab |
| Tailscale account | Free tier, installed on Alienware and all managed devices |
| MaxMind account | Free GeoLite2 account for GeoIP databases |

---

## Phase 1 — OPNsense WireGuard Server

### Step 1.1 — Create WireGuard Instance

Navigate to **VPN → WireGuard → Instances** → click **+**

| Field | Value |
|-------|-------|
| Enabled | ✅ checked |
| Name | `wg-honeypot` |
| Listen Port | `51820` |
| Tunnel Address | `10.10.10.1/30` |
| Disable Routes | ☐ unchecked |
| Peers | *(leave empty — add after VPS is provisioned)* |

Click **Save**. OPNsense auto-generates the keypair.

**Action required:** Copy the generated Public Key and save it securely. This is the OPNsense public key that goes into the VPS WireGuard config.

### Step 1.2 — Assign WireGuard Interface

Navigate to **Interfaces → Assignments**

Find `wg0 (WireGuard - wg-honeypot)` in the unassigned interfaces. Assign it and name it `HoneypotOPT6`. Save.

Navigate to the new `[HoneypotOPT6]` interface. Verify:
- Enable Interface: ✅ checked
- IPv4 Configuration Type: None *(WireGuard manages its own IP)*

Save.

### Step 1.3 — Add OPT6 Firewall Rule

Navigate to **Firewall → Rules → HoneypotOPT6** → click **+**

| Field | Value |
|-------|-------|
| Action | Pass |
| Interface | HoneypotOPT6 |
| Protocol | Any |
| Source | `10.10.10.0/30` |
| Destination | `192.168.10.0/24` |
| Description | `Allow VPS honeypot to reach VLAN 10 for log forwarding` |

Save and Apply.

---

## Phase 2 — DigitalOcean VPS Provisioning

### Step 2.1 — Create Droplet

Settings used:
- **Region:** New York — NYC1
- **OS:** Ubuntu 24.04 LTS x64
- **Plan:** Basic, Shared CPU, Regular
- **Size:** 1GB RAM / 1 vCPU / 25GB SSD ($6/month)
- **Hostname:** `ubuntu-home-server-droplet`
- **Authentication:** Password (SSH key added in Phase 3)

After provisioning: **Public IP assigned: 174.138.35.11**

### Step 2.2 — Create Cloud Firewall

Navigate to **Networking → Firewalls** → Create Firewall → name: `cowrie-honeypot`

**Inbound rules:**

| Type | Protocol | Port | Sources |
|------|----------|------|---------|
| SSH | TCP | 22 | All IPv4, All IPv6 |
| Custom | TCP | 23 | All IPv4, All IPv6 |
| HTTP | TCP | 80 | All IPv4, All IPv6 |
| HTTPS | TCP | 443 | All IPv4, All IPv6 |
| Custom | TCP | 21 | All IPv4, All IPv6 |
| Custom | TCP | 445 | All IPv4, All IPv6 |
| Custom | TCP | 1433 | All IPv4, All IPv6 |
| MySQL | TCP | 3306 | All IPv4, All IPv6 |
| Custom | TCP | 2222 | `100.72.171.104` (Tailscale only) |
| Custom | UDP | 51820 | All IPv4, All IPv6 |

**Outbound rules:** Allow all TCP, UDP, ICMP

Apply firewall to the Droplet.

---

## Phase 3 — VPS Initial Setup

SSH into the VPS with the root password set during provisioning:
```bash
ssh root@174.138.35.11
```

### Step 3.1 — Verify environment
```bash
uname -a && free -h
# Linux ubuntu-home-server-droplet 6.8.0-71-generic
# Mem: 961Mi  Swap: 511Mi (pre-existing from base image)
```

### Step 3.2 — Move SSH to port 2222

**Critical: do this before adding SSH key to prevent lockout.**

```bash
systemctl stop ssh.socket
systemctl disable ssh.socket
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config
systemctl restart ssh
ss -tlnp | grep ssh
# Expected: LISTEN 0 128 0.0.0.0:2222
```

### Step 3.3 — Add Alienware SSH public key

```bash
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFj7VztxX24ucdtYN7a07Z7bE4oHfQPzWeMrcZxLIyb0 tycee@TyceErickson" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

**Verify from Alienware before continuing:**
```bash
ssh -p 2222 root@174.138.35.11
# Must connect without password before proceeding
```

### Step 3.4 — Install Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up
# Authenticate via URL provided
tailscale ip -4
# Result: 100.89.15.57
```

### Step 3.5 — Install dependencies

```bash
apt update && apt upgrade -y
apt install -y wireguard docker.io docker-compose fail2ban unattended-upgrades
systemctl enable docker && systemctl start docker
```

### Step 3.6 — Disable password auth for real SSH

```bash
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
systemctl restart ssh
```

---

## Phase 4 — WireGuard Tunnel Setup

### Step 4.1 — Generate VPS keypair

```bash
wg genkey | tee /etc/wireguard/vps_private.key | wg pubkey > /etc/wireguard/vps_public.key
chmod 600 /etc/wireguard/vps_private.key
cat /etc/wireguard/vps_public.key
# Save this public key — goes into OPNsense peer config
```

### Step 4.2 — Write WireGuard config

```bash
VPS_PRIVATE=$(cat /etc/wireguard/vps_private.key)

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $VPS_PRIVATE
Address = 10.10.10.2/30
ListenPort = 51820

[Peer]
PublicKey = <OPNSENSE_PUBLIC_KEY>
AllowedIPs = 10.10.10.1/32, 192.168.10.0/24
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf
```

Replace `<OPNSENSE_PUBLIC_KEY>` with the key saved in Step 1.1.

### Step 4.3 — Start WireGuard

```bash
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
wg show
```

### Step 4.4 — Add VPS as peer in OPNsense

Navigate to **VPN → WireGuard → Peers** → click **+**

| Field | Value |
|-------|-------|
| Name | `ubuntu-home-server-droplet` |
| Public Key | *(VPS public key from Step 4.1)* |
| Allowed IPs | `10.10.10.2/32` |
| Endpoint host | `174.138.35.11` |
| Endpoint port | `51820` |
| Instances | `wg-honeypot` |
| Keepalive interval | `25` |

Save → Apply.

### Step 4.5 — Verify tunnel handshake

```bash
wg show
# Expected: latest handshake: X seconds ago
# transfer: XXX B received, XXX B sent
```

---

## Phase 5 — Ubuntu Server Routing

The tunnel passes through OPNsense but Ubuntu Server needs a return route to send traffic back through the tunnel correctly (asymmetric routing fix).

### Step 5.1 — Add persistent static route

Edit `/etc/netplan/50-cloud-init.yaml`:

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

```bash
sudo netplan apply
ip route show | grep 10.10.10
# Expected: 10.10.10.0/30 via 192.168.10.1 dev enp0s2 proto static
```

### Step 5.2 — Test tunnel connectivity

```bash
# From VPS:
ssh -i /root/.ssh/cowrie_sync terickson@192.168.10.4
# Expected: successful login to Ubuntu Server
```

---

## Phase 6 — Cowrie Deployment

### Step 6.1 — Create directory structure

```bash
mkdir -p /opt/cowrie/{logs,dl,nginx-logs,dionaea-logs,dionaea-malware}
chown -R 999:999 /opt/cowrie/logs
chown -R 999:999 /opt/cowrie/dl
```

### Step 6.2 — Write docker-compose.yml

See `config/docker-compose.yml` in this repository for the complete configuration.

### Step 6.3 — Deploy all containers

```bash
cd /opt/cowrie
docker-compose pull
docker-compose up -d
docker ps
```

Expected output:
```
cowrie          Up    0.0.0.0:22->2222/tcp, 0.0.0.0:23->2223/tcp
nginx-honeypot  Up    0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
dionaea         Up    0.0.0.0:21->21/tcp, 0.0.0.0:445->445/tcp, ...
```

### Step 6.4 — Verify Cowrie is logging

```bash
# Wait 2 minutes after deployment for first connections
cat /opt/cowrie/logs/cowrie.json | grep "eventid" | wc -l
# Expected: >0 within 5 minutes of going live
```

---

## Phase 7 — Log Forwarding Pipeline

### Step 7.1 — Generate sync SSH key

```bash
ssh-keygen -t ed25519 -f /root/.ssh/cowrie_sync -N ""
cat /root/.ssh/cowrie_sync.pub
```

### Step 7.2 — Add key to Ubuntu Server

On Ubuntu Server:
```bash
sudo mkdir -p /opt/cowrie-logs/{nginx,dionaea}
sudo chown terickson:terickson /opt/cowrie-logs
echo "<VPS_COWRIE_SYNC_PUBLIC_KEY>" >> /home/terickson/.ssh/authorized_keys
```

### Step 7.3 — Set up rsync cron

```bash
cat > /etc/cron.d/cowrie-sync << 'EOF'
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' /opt/cowrie/logs/cowrie.json terickson@192.168.10.4:/opt/cowrie-logs/
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' /opt/cowrie/nginx-logs/ terickson@192.168.10.4:/opt/cowrie-logs/nginx/
*/15 * * * * root rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' /opt/cowrie/dionaea-logs/ terickson@192.168.10.4:/opt/cowrie-logs/dionaea/
EOF
chmod 644 /etc/cron.d/cowrie-sync
```

### Step 7.4 — Test manual rsync

```bash
rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' \
  /opt/cowrie/logs/cowrie.json terickson@192.168.10.4:/opt/cowrie-logs/
# Expected: sent XXXXX bytes  received XXX bytes
```

---

## Phase 8 — GeoIP Enrichment

### Step 8.1 — Download MaxMind databases

On Ubuntu Server (requires free MaxMind account):

```bash
sudo mkdir -p /opt/geoip
sudo chown terickson:terickson /opt/geoip
cd /opt/geoip

LICENSE_KEY="<YOUR_MAXMIND_LICENSE_KEY>"

curl -L -u "1350638:${LICENSE_KEY}" \
  "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" \
  -o GeoLite2-City.tar.gz

curl -L -u "1350638:${LICENSE_KEY}" \
  "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz" \
  -o GeoLite2-ASN.tar.gz

tar -xzf GeoLite2-City.tar.gz && mv GeoLite2-City_*/GeoLite2-City.mmdb .
tar -xzf GeoLite2-ASN.tar.gz && mv GeoLite2-ASN_*/GeoLite2-ASN.mmdb .
```

### Step 8.2 — Install Python dependency

```bash
pip3 install geoip2 --break-system-packages
```

### Step 8.3 — Deploy enrichment script

Copy `pipeline/enrich_logs.py` to `/opt/geoip/enrich_logs.py` on Ubuntu Server.

### Step 8.4 — Set up enrichment cron

```bash
echo "0 * * * * terickson python3 /opt/geoip/enrich_logs.py >> /var/log/geoip-enrich.log 2>&1" \
  | sudo tee -a /etc/cron.d/geoip-enrich
sudo chmod 644 /etc/cron.d/geoip-enrich
```

### Step 8.5 — Verify enrichment

```bash
python3 /opt/geoip/enrich_logs.py
# Expected output:
# [+] Loading GeoIP databases...
# [+] Enriched XXXX events (0 skipped)
# [+] Top 10 attacker countries:
#     XXX events  [Country]
```

---

## Phase 9 — Hardening

### fail2ban

```bash
cat > /etc/fail2ban/jail.d/sshd-2222.conf << 'EOF'
[sshd]
enabled = true
port = 2222
maxretry = 3
bantime = 86400
EOF
systemctl enable fail2ban && systemctl start fail2ban
fail2ban-client status sshd
```

### Cowrie containment (iptables)

```bash
# Block outbound connections from Cowrie's UID (999)
# Prevents escape attempts from making external connections
iptables -I OUTPUT -m owner --uid-owner 999 -j DROP
apt install -y iptables-persistent
iptables-save > /etc/iptables/rules.v4
```

### Unattended security updates

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
# Select: Yes
```

---

## Verification Checklist

Run this verification after full deployment:

```bash
# 1. All containers running
docker ps | grep -E "cowrie|nginx|dionaea"

# 2. Events being captured
cat /opt/cowrie/logs/cowrie.json | grep "eventid" | wc -l

# 3. WireGuard tunnel active
wg show | grep "latest handshake"

# 4. rsync to Ubuntu Server working
rsync -av -e 'ssh -i /root/.ssh/cowrie_sync -o StrictHostKeyChecking=no' \
  /opt/cowrie/logs/cowrie.json terickson@192.168.10.4:/opt/cowrie-logs/

# 5. fail2ban running
fail2ban-client status sshd

# 6. Disk healthy
df -h /

# 7. Cron jobs in place
cat /etc/cron.d/cowrie-sync
```

All 7 checks must pass before the capture period begins.

---

## Capture Period

- **Start:** May 21, 2026 18:14 UTC
- **End:** May 28, 2026 18:14 UTC
- **Duration:** 7 days
- **Monitoring:** Daily `wc -l /opt/cowrie-logs/cowrie.json && df -h /`
