#!/bin/bash
# role_setup.sh - Harden Pi Zero 2 and configure based on role (concentrator | redirector)
# Usage: sudo ./role_setup.sh <concentrator|redirector>
# Hybrid version: combines reliable iptables approach with improved error handling and security features
set -euo pipefail

ROLE=${1:-""}
if [[ -z "$ROLE" ]]; then
  echo "Usage: $0 <concentrator|redirector>"
  exit 1
fi

USER="ops"
SSH_DIR="/home/$USER/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
WG_DIR="/etc/wireguard"

# utility: detect primary uplink interface (used for NAT rule on concentrator)
detect_uplink_iface() {
  local iface
  iface=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ { for(i=1;i<=NF;i++){ if ($i=="dev") { print $(i+1); exit } } }')
  if [[ -z "$iface" ]]; then
    iface="wlan0"
  fi
  echo "$iface"
}

echo "[*] Role: $ROLE"
echo "[*] Updating apt & upgrading packages..."
apt update && apt -y full-upgrade

echo "[*] Ensure SSH directory for $USER exists and permissions are correct (if present)..."
if id -u "$USER" >/dev/null 2>&1; then
  mkdir -p "$SSH_DIR"
  chown "$USER":"$USER" "$SSH_DIR"
  chmod 700 "$SSH_DIR"
  if [[ -f "$AUTHORIZED_KEYS" ]]; then
    chown "$USER":"$USER" "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
  fi
else
  echo "[!] User $USER does not exist. If you preseeded with Raspberry Imager, ensure ops user was created."
fi

echo "[*] Harden SSH (disable root login, prefer keys)..."
# Keep password auth disabled for security (change to 'yes' if you need fallback access)
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
systemctl restart ssh

echo "[*] Installing packages: ufw fail2ban wireguard"
DEBIAN_FRONTEND=noninteractive apt -y install ufw fail2ban wireguard

# Verify install
for pkg in ufw fail2ban wireguard; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "[!] ERROR: Package $pkg is missing or not fully installed"
        exit 1
    fi
done

# nginx only for redirector role
if [[ "$ROLE" == "redirector" ]]; then
  apt -y install nginx
  if ! dpkg -s nginx >/dev/null 2>&1; then
      echo "[!] ERROR: nginx failed to install"
      exit 1
  fi
fi

echo "[*] Configure UFW baseline (simple firewall, no NAT integration)..."

# Reset UFW to clean state if there are existing issues
echo "[*] Resetting UFW to clean state..."
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh

# allow common web ports for redirector
if [[ "$ROLE" == "redirector" ]]; then
  ufw allow http
  ufw allow https
fi

# WireGuard port will be opened below after config is written
# enable UFW (idempotent)
ufw --force enable

# === WireGuard key generation & secure placement ===
echo "[*] Preparing WireGuard keys and config..."
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

# key filenames and network config per role
if [[ "$ROLE" == "concentrator" ]]; then
  PRIV_FILE="$WG_DIR/concentrator_private.key"
  PUB_FILE="$WG_DIR/concentrator_public.key"
  WG_LISTEN_PORT=51820
  LOCAL_WG_ADDR="10.44.0.1/24"
elif [[ "$ROLE" == "redirector" ]]; then
  PRIV_FILE="$WG_DIR/redirector_private.key"
  PUB_FILE="$WG_DIR/redirector_public.key"
  WG_LISTEN_PORT=54156
  LOCAL_WG_ADDR="10.44.0.2/32"
else
  echo "[!] Unknown role: $ROLE"
  exit 1
fi

# generate keys if absent (private key never printed to console)
if [[ ! -f "$PRIV_FILE" ]]; then
  echo "[*] Generating WireGuard keypair for $ROLE..."
  umask 077
  wg genkey | tee "$PRIV_FILE" | wg pubkey > "$PUB_FILE"
  chmod 600 "$PRIV_FILE"
  chmod 644 "$PUB_FILE"
  chown root:root "$PRIV_FILE" "$PUB_FILE"
else
  echo "[*] Existing keypair found for $ROLE."
fi

# read public key for operator convenience (private key not displayed for security)
ROLE_PUB_KEY=$(cat "$PUB_FILE")
echo ""
echo "[*] $ROLE public key (copy this where required):"
echo "$ROLE_PUB_KEY"
echo ""

# === write wg0.conf (no inline private key, loaded via PostUp) ===
WG_CONF="$WG_DIR/wg0.conf"
UPLINK_IF=$(detect_uplink_iface)

if [[ "$ROLE" == "concentrator" ]]; then
  cat > "$WG_CONF" <<EOF
[Interface]
Address = ${LOCAL_WG_ADDR}
ListenPort = ${WG_LISTEN_PORT}
# Load private key and configure routing/NAT via PostUp (reliable iptables approach)
PostUp = wg set %i private-key ${PRIV_FILE}; sysctl -w net.ipv4.ip_forward=1; iptables -I FORWARD -i %i -j ACCEPT; iptables -I FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.44.0.0/24 -o ${UPLINK_IF} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.44.0.0/24 -o ${UPLINK_IF} -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; sysctl -w net.ipv4.ip_forward=0

# Peers: add [Peer] sections manually or via automation (public keys only)
# Example:
# [Peer]
# PublicKey = <redirector_public_key>
# AllowedIPs = 10.44.0.2/32

EOF

elif [[ "$ROLE" == "redirector" ]]; then
  cat > "$WG_CONF" <<EOF
[Interface]
Address = ${LOCAL_WG_ADDR}
ListenPort = ${WG_LISTEN_PORT}
# Load private key and minimal firewall rules
PostUp = wg set %i private-key ${PRIV_FILE}; iptables -I INPUT -p udp --dport ${WG_LISTEN_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${WG_LISTEN_PORT} -j ACCEPT

[Peer]
# Populate this block on operator machine:
# PublicKey = <concentrator_public_key>
# AllowedIPs = 10.44.0.0/24
# Endpoint = <concentrator_lan_or_public_ip>:51820
# PersistentKeepalive = 25

EOF
fi

# secure file permissions and make immutable
chown root:root "$WG_CONF"
chmod 600 "$WG_CONF"
chattr +i "$WG_CONF"
echo "[*] WireGuard config written to $WG_CONF and marked immutable (chattr +i)"

# open WireGuard port in UFW
ufw allow "${WG_LISTEN_PORT}/udp"

# === Persist IP forwarding in sysctl.conf ===
echo "[*] Persist net.ipv4.ip_forward=1 in /etc/sysctl.conf..."
if ! grep -q '^net.ipv4.ip_forward=' /etc/sysctl.conf; then
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
else
  sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 >/dev/null || true

# === Configure fail2ban SSH jail ===
echo "[*] Configuring fail2ban SSH jail (/etc/fail2ban/jail.local)..."
cat > /etc/fail2ban/jail.local <<'JAIL_EOF'
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
JAIL_EOF

systemctl enable fail2ban
systemctl restart fail2ban

# === Enable and start WireGuard ===
echo "[*] Enabling and starting wg-quick@wg0..."
systemctl enable wg-quick@wg0

# attempt to start/restart (capture exit code for diagnostics)
set +e
systemctl restart wg-quick@wg0
WG_EXIT=$?
set -e
if [[ $WG_EXIT -ne 0 ]]; then
  echo "[!] Warning: wg-quick@wg0 restart returned exit code $WG_EXIT"
  echo "    Check logs: journalctl -u wg-quick@wg0 -n 50"
fi

# === Role-specific configuration (nginx for redirector) ===
if [[ "$ROLE" == "redirector" ]]; then
  echo "[*] Configuring nginx redirector site with OPSEC obfuscation..."
  
  # Create hosts entry for domain-based obfuscation
  if ! grep -q "internal-api.knightsgambitsecurity.com" /etc/hosts; then
    echo "10.44.0.10 internal-api.knightsgambitsecurity.com" >> /etc/hosts
    echo "[*] Added internal DNS mapping for C2 server"
  fi
  
  cat > /etc/nginx/sites-available/redirector <<'NGINX_EOF'
server {
    listen 80;
    server_name knightsgambitsecurity.com www.knightsgambitsecurity.com;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-Robots-Tag "noindex, nofollow" always;

    # Obfuscated C2 endpoints - appear as business API calls
    location /api/v1/status {
        # Sliver C2 endpoint
        proxy_pass http://internal-api.knightsgambitsecurity.com:80/sliver;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
    }
    
    location /resources/updates {
        # BeEF endpoint  
        proxy_pass http://internal-api.knightsgambitsecurity.com:3000/beef;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ =404;
    }
    
    # Block common security scanner paths
    location ~ /\.(ht|git|env) {
        deny all;
        return 404;
    }
}
NGINX_EOF

  # Create believable business website content
  mkdir -p /var/www/html
  cat > /var/www/html/index.html <<'HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Knights Gambit Security - Cybersecurity Consulting</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; border-bottom: 3px solid #007acc; }
        .services { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .service { background: #f9f9f9; padding: 15px; border-left: 4px solid #007acc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Knights Gambit Security</h1>
        <p>Professional cybersecurity consulting and penetration testing services.</p>
        
        <div class="services">
            <div class="service">
                <h3>Penetration Testing</h3>
                <p>Comprehensive security assessments to identify vulnerabilities.</p>
            </div>
            <div class="service">
                <h3>Security Consulting</h3>
                <p>Expert guidance on cybersecurity strategy and implementation.</p>
            </div>
            <div class="service">
                <h3>Compliance Auditing</h3>
                <p>Ensuring your organization meets regulatory requirements.</p>
            </div>
        </div>
        
        <hr>
        <p><strong>Contact:</strong> info@knightsgambitsecurity.com</p>
        <p><small>© 2024 Knights Gambit Security LLC. All rights reserved.</small></p>
    </div>
</body>
</html>
HTML_EOF

  ln -sf /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/
  # remove default site to avoid conflicts
  rm -f /etc/nginx/sites-enabled/default
  
  # test and restart nginx
  if nginx -t; then
    systemctl restart nginx
    echo "[*] Nginx restarted successfully with obfuscated configuration"
    echo "[*] C2 endpoints: /api/v1/status (Sliver), /resources/updates (BeEF)"
  else
    echo "[!] Nginx configuration test failed - check logs with 'nginx -t'"
  fi
fi

# === Comprehensive diagnostics ===
echo ""
echo "=== DIAGNOSTICS ==="
echo "[*] WireGuard interface status:"
wg show || echo "[!] WireGuard interface not active"
echo ""

echo "[*] Network interface addresses:"
ip -4 addr show | grep -E "(inet|wg0|${UPLINK_IF})" || true
echo ""

echo "[*] Active UDP listeners (WireGuard ports):"
ss -unlp | grep -E "51820|54156|wg" || echo "No WireGuard ports found listening"
echo ""

echo "[*] iptables filter rules:"
iptables -L FORWARD -v -n --line-numbers | head -20 || true
echo ""

echo "[*] iptables NAT rules:"
iptables -t nat -L POSTROUTING -v -n --line-numbers | head -10 || true
echo ""

echo "[*] UFW status:"
ufw status verbose || true
echo ""

echo "[*] fail2ban SSH jail status:"
fail2ban-client status sshd 2>/dev/null || echo "fail2ban sshd jail not active yet"
echo ""

echo "[*] System forwarding status:"
echo "net.ipv4.ip_forward = $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'unknown')"
echo ""

# connectivity test to expected peer addresses
if [[ "$ROLE" == "concentrator" ]]; then
  echo "[*] Testing connectivity to redirector WG IP (10.44.0.2)..."
  ping -c 3 -W 2 10.44.0.2 || echo "[!] Ping to redirector failed (expected if peer not configured yet)"
elif [[ "$ROLE" == "redirector" ]]; then
  echo "[*] Testing connectivity to concentrator WG IP (10.44.0.1)..."
  ping -c 3 -W 2 10.44.0.1 || echo "[!] Ping to concentrator failed (expected if peer not configured yet)"
fi

echo ""
echo "=== SETUP COMPLETE FOR ROLE: $ROLE ==="
echo ""
echo "NEXT STEPS:"
if [[ "$ROLE" == "concentrator" ]]; then
  echo "  1. Add [Peer] blocks to /etc/wireguard/wg0.conf for each client (redirector, laptops, etc.)"
  echo "     Example:"
  echo "     [Peer]"
  echo "     PublicKey = <peer_public_key>"
  echo "     AllowedIPs = 10.44.0.X/32"
  echo ""
  echo "  2. Remove immutable flag, edit config, then restore:"
  echo "     chattr -i /etc/wireguard/wg0.conf"
  echo "     # edit the file"
  echo "     chattr +i /etc/wireguard/wg0.conf"
  echo ""
  echo "  3. Restart WireGuard: systemctl restart wg-quick@wg0"
elif [[ "$ROLE" == "redirector" ]]; then
  echo "  1. Edit /etc/wireguard/wg0.conf to add concentrator details:"
  echo "     chattr -i /etc/wireguard/wg0.conf"
  echo "     # Add concentrator public key and endpoint"
  echo "     chattr +i /etc/wireguard/wg0.conf"
  echo ""
  echo "  2. Update nginx proxy_pass in /etc/nginx/sites-available/redirector"
  echo "  3. Restart both services:"
  echo "     systemctl restart wg-quick@wg0"
  echo "     systemctl restart nginx"
fi
echo ""
echo "VERIFICATION:"
echo "  - Use 'wg show' to confirm handshakes and data transfer"
echo "  - Check 'systemctl status wg-quick@wg0' for any errors"
echo "  - Monitor logs: journalctl -u wg-quick@wg0 -f"
echo ""
echo "SECURITY NOTES:"
echo "  - Config file is now immutable (chattr +i) - use 'chattr -i' before editing"
echo "  - Private keys are in $WG_DIR with 600 permissions"
echo "  - SSH is hardened (no root login, no password auth)"
echo "  - fail2ban is active for SSH brute-force protection"
echo "  - Rotate/remove private keys between engagements as needed"
echo ""

exit 0