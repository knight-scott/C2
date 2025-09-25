# Field Kit Deployment — C2 + Redirector / Concentrator Framework

This repository contains configuration, setup scripts, and deployment notes for a portable, modular field kit. The kit is designed for red-team operations, red-team training, and authorised security research. The design emphasizes secure defaults, reproducible deployments, and ephemeral, recoverable infrastructure.

> **Disclaimer:** This repository is for educational, lab, or authorized penetration testing purposes only. Do not deploy against systems without explicit permission.

---

## Quick Start Checklist

**Time estimate: 45-60 minutes for complete Tier 2 deployment**

### Pre-deployment (15 minutes)
- [ ] Flash 2x Pi Zero 2W with Raspberry Pi OS Lite 32-bit
- [ ] Enable SSH, create `ops` user, disable password auth in Imager
- [ ] Add your SSH public key to authorized_keys during imaging
- [ ] Clone this repo to both devices: `git clone https://github.com/knight-scott/C2.git`

### Device Setup (20 minutes)
- [ ] **Concentrator Pi**: `sudo ./role_setup.sh concentrator`
- [ ] **Redirector Pi**: `sudo ./role_setup.sh redirector`
- [ ] Copy public keys between devices (displayed at end of each setup)

### Network Configuration (10 minutes)
- [ ] Edit `/etc/wireguard/wg0.conf` on both devices (use `chattr -i` first)
- [ ] Add peer configurations and endpoints
- [ ] Restart WireGuard: `systemctl restart wg-quick@wg0`
- [ ] Verify with `wg show` - should show handshakes and transfer bytes

### Validation (5 minutes)
- [ ] Test VPN connectivity: `ping 10.44.0.1` and `ping 10.44.0.2`
- [ ] Test proxy path: `curl http://redirector-ip/cdn`
- [ ] Deploy to field positions and verify remote connectivity

---

## Hardware Inventory

### Tier 1 — Lab/Minimal Setup
| Component | Quantity | Purpose | Estimated Cost |
|-----------|----------|---------|----------------|
| Yuzuki Avaota-A1 SBC | 1 | Primary C2 host | $150-200 |
| Raspberry Pi Zero 2 W | 1 | Redirector | $15-20 |
| MicroSD cards (32GB+) | 2 | Storage | $10-15 each |
| Power banks/adapters | 2 | Field power | $20-40 each |

### Tier 2 — Field Ready (Recommended)
Add to Tier 1:
| Component | Quantity | Purpose | Estimated Cost |
|-----------|----------|---------|----------------|
| Raspberry Pi Zero 2 W | +1 | WireGuard concentrator | $15-20 |
| 4G/5G hotspot (GL.iNet GL-E750) | 1 | Internet connectivity | $150-200 |
| Travel router (GL.iNet GL-MT300N-V2) | 1 | Local networking | $25-35 |
| USB Ethernet adapters | 2-3 | Wired connectivity | $10-15 each |
| SIM card with data plan | 1+ | Mobile connectivity | Variable |

### Tier 3 — Full Engagement Kit
Add to Tier 2:
| Component | Quantity | Purpose | Estimated Cost |
|-----------|----------|---------|----------------|
| WiFi Pineapple | 1 | Wireless attacks | $100-150 |
| Flipper Zero | 1 | RF/Hardware | $170-200 |
| USB Rubber Ducky | 1 | HID attacks | $50-80 |
| Packet Squirrel | 1 | Network implant | $60-80 |

---

## Network Architecture

### Default IP Assignments
```
VPN Subnet: 10.44.0.0/24
├── 10.44.0.1    - Concentrator (WireGuard hub)
├── 10.44.0.2    - Primary redirector
├── 10.44.0.3    - Secondary redirector (if deployed)
├── 10.44.0.10   - C2 server (Avaota-A1)
├── 10.44.0.50   - Operator laptop
└── 10.44.0.100+ - Additional devices
```

### Port Assignments
```
Concentrator:  51820/udp - WireGuard
Redirector:    54156/udp - WireGuard
               80,443/tcp - HTTP/HTTPS proxy
C2 Server:     Various    - C2 framework specific
```

---

## Step-by-Step Deployment

### Phase 1: Device Preparation

#### 1.1 Flash SD Cards (5 minutes each)
Use Raspberry Pi Imager with these settings:
- **OS**: Raspberry Pi OS Lite (32-bit) - **NOT 64-bit**
- **Advanced Options**:
  - Enable SSH with public key authentication
  - Username: `ops`, disable password authentication  
  - Configure WiFi (for initial setup)
  - Set hostname: `concentrator` or `redirector-01`

#### 1.2 Initial SSH Connection
```bash
# Find device on network
nmap -sn 192.168.1.0/24 | grep -B2 "Raspberry Pi"

# SSH in (password auth should be disabled)
ssh ops@<device-ip>
```

#### 1.3 Clone Repository and Run Setup
```bash
# On each device
sudo apt update
git clone https://github.com/knight-scott/C2.git field-kit
cd field-kit
sudo ./role_setup.sh concentrator  # or 'redirector'
```

**Expected output**: Script will display the device's WireGuard public key. **Copy this immediately**.

### Phase 2: Peer Configuration

#### 2.1 Configure Concentrator
```bash
# Remove immutable flag
sudo chattr -i /etc/wireguard/wg0.conf

# Edit config - add these peer blocks:
sudo nano /etc/wireguard/wg0.conf
```

Add peer sections:
```
[Peer]
# Redirector
PublicKey = <redirector_public_key_from_setup>
AllowedIPs = 10.44.0.2/32

[Peer] 
# Operator laptop
PublicKey = <laptop_public_key>
AllowedIPs = 10.44.0.50/32

[Peer]
# C2 Server
PublicKey = <c2_server_public_key>
AllowedIPs = 10.44.0.10/32
```

```bash
# Restore immutable flag and restart
sudo chattr +i /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

#### 2.2 Configure Redirector
```bash
# Remove immutable flag  
sudo chattr -i /etc/wireguard/wg0.conf

# Edit the [Peer] section
sudo nano /etc/wireguard/wg0.conf
```

Update the peer block:
```
[Peer]
PublicKey = <concentrator_public_key_from_setup>
AllowedIPs = 10.44.0.0/24
Endpoint = <concentrator_public_or_lan_ip>:51820
PersistentKeepalive = 25
```

```bash
# Restore immutable flag and restart
sudo chattr +i /etc/wireguard/wg0.conf  
sudo systemctl restart wg-quick@wg0
```

### Phase 3: Validation and Testing

#### 3.1 Verify WireGuard Connectivity
```bash
# On both devices - should show handshake times and transfer bytes
sudo wg show

# Test ping between VPN IPs
ping 10.44.0.1  # from redirector to concentrator
ping 10.44.0.2  # from concentrator to redirector
```

#### 3.2 Configure Redirector Proxy
```bash
# Edit nginx config to point to your C2
sudo nano /etc/nginx/sites-available/redirector
# Change proxy_pass to: http://10.44.0.10:8888 (or your C2 port)

sudo systemctl restart nginx
```

#### 3.3 Test Proxy Path
```bash
# From external network - should reach C2 through VPN
curl -v http://<redirector-public-ip>/cdn
```

---

## Troubleshooting Guide

### WireGuard Issues

**No handshake showing in `wg show`:**
```bash
# Check if WireGuard is listening
sudo ss -unlp | grep 51820
sudo ss -unlp | grep 54156

# Check firewall
sudo ufw status
sudo iptables -L -n | grep -E "51820|54156"

# Check logs
sudo journalctl -u wg-quick@wg0 -n 50
```

**Handshake but no connectivity:**
```bash
# Check routing
ip route show table all | grep wg0

# Verify IP forwarding (concentrator only)
cat /proc/sys/net/ipv4/ip_forward  # should be 1

# Check NAT rules (concentrator only)
sudo iptables -t nat -L -n -v
```

**Can't reach internet through concentrator:**
```bash
# Verify MASQUERADE rule exists
sudo iptables -t nat -L POSTROUTING -v -n | grep MASQUERADE

# Check uplink interface
ip route get 8.8.8.8
```

### Common Deployment Issues

| Problem | Symptoms | Solution |
|---------|----------|-----------|
| SSH key auth failing | Password prompt appears | Re-flash SD card with correct SSH key |
| WireGuard won't start | Service fails to start | Check `journalctl -u wg-quick@wg0` for syntax errors |
| No internet on devices | Can ping VPN IPs but not internet | Check concentrator NAT rules and uplink |
| Proxy not working | 502/503 errors on `/cdn` path | Verify C2 is listening on specified port |
| Can't edit wg0.conf | Permission denied | Use `chattr -i` before editing |

---

## Field Deployment Scenarios

### Scenario A: Single Building Engagement
**Hardware**: Tier 1 + travel router
1. Deploy concentrator in secure location (wired to travel router)
2. Place redirector(s) in target network DMZ or public-facing segments
3. Operator connects via laptop to concentrator (wired or VPN)

### Scenario B: Remote/Mobile Operations  
**Hardware**: Tier 2 complete
1. Concentrator connects via 4G/5G hotspot for internet
2. Redirector(s) deployed in target locations with separate internet
3. All devices mesh through WireGuard overlay
4. Operator can be fully remote

### Scenario C: Multi-Vector Engagement
**Hardware**: Tier 3 complete
1. Base setup per Scenario A or B
2. Add wireless attack platform (Pineapple) on separate Pi
3. Deploy physical implants (Packet Squirrel) inline
4. Use Flipper/Ducky for physical access components

---

## Security Checklists

### Pre-Deployment Security
- [ ] All default passwords changed
- [ ] SSH keys unique per engagement  
- [ ] WireGuard keys generated on-device (never transmitted)
- [ ] Configs marked immutable (`chattr +i`)
- [ ] fail2ban enabled and configured
- [ ] UFW baseline applied

### Post-Engagement Cleanup
- [ ] Wipe SD cards or re-image completely
- [ ] Generate new SSH keys for next engagement
- [ ] Clear any cached credentials from operators' machines
- [ ] Document lessons learned and config changes needed

### Operational Security
- [ ] Concentrator never directly exposed to internet
- [ ] C2 server only accessible via VPN overlay
- [ ] Redirectors present believable decoy content
- [ ] All administrative access goes through concentrator (jump host)
- [ ] Monitor fail2ban logs for unauthorized access attempts

---

## Quick Command Reference

### Essential Commands
```bash
# WireGuard status
sudo wg show

# Check services
sudo systemctl status wg-quick@wg0
sudo systemctl status nginx
sudo systemctl status fail2ban

# Network diagnostics
ip addr show wg0
ss -unlp | grep -E "51820|54156|80|443"
sudo iptables -t nat -L -v -n

# Edit protected configs
sudo chattr -i /etc/wireguard/wg0.conf
# ... make changes ...
sudo chattr +i /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

### Log Analysis
```bash
# WireGuard logs
sudo journalctl -u wg-quick@wg0 -f

# nginx access/error logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log  

# fail2ban status
sudo fail2ban-client status sshd
```

---

## Hardware Sources and Alternatives

### Recommended Suppliers
- **Pi Zero 2W**: Adafruit, Pi Foundation, or local electronics suppliers
- **Avaota-A1**: Check availability through Yuzuki distributors
- **GL.iNet devices**: Amazon, official GL.iNet store
- **Hak5 gear**: Official Hak5 shop for WiFi Pineapple, etc.

### Hardware Alternatives
| Original | Alternative | Notes |
|----------|-------------|-------|
| Avaota-A1 | Raspberry Pi 4B 8GB | More common, slightly larger |
| GL.iNet GL-E750 | Netgear MR1100 | More carrier support |
| Pi Zero 2W | Orange Pi Zero 2W | Similar specs, different GPIO |

---

## Contributing and Roadmap

### Immediate Improvements Needed
- [ ] Add `add-peer.sh` helper script
- [ ] Create Ansible playbook for multi-device deployment
- [ ] Build container images for C2 deployment
- [ ] Add monitoring/alerting stack

### Deployment Templates
- [ ] Pre-configured SD card images per role
- [ ] Docker Compose stack for C2 + supporting services
- [ ] Terraform templates for cloud-based concentrators

---

**Legal and Ethical Notice**: This project is intended for lawful, authorized security testing, training, and research. Unauthorized use against networks or systems you do not own or have explicit permission to test is illegal. Always obtain written authorization before conducting penetration testing or red team activities.