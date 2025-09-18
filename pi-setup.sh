#!/bin/bash
# role_setup.sh - Harden Pi Zero 2 and configure based on role (concentrator | redirector)
# Usage: sudo ./role_setup.sh <concentrator|redirector>
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
  # try to get interface used to reach the internet
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
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
systemctl restart ssh

echo "[*] Installing packages: ufw fail2ban wireguard nginx (if needed) ..."
apt -y install ufw fail2ban wireguard

# nginx only for redirector if role chosen
if [[ "$ROLE" == "redirector" ]]; then
  apt -y install nginx
fi

echo "[*] Configure UFW baseline..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
# allow common web ports for redirector
if [[ "$ROLE" == "redirector" ]]; then
  ufw allow http
  ufw allow https
fi
# concentrator WireGuard port open below after we write config
# enable UFW (idempotent)
ufw --force enable

# === WireGuard key generation & secure placement ===
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

# key filenames per role
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

# generate keys if absent (private key never printed)
if [[ ! -f "$PRIV_FILE" ]]; then
  echo "[*] Generating WireGuard keypair for $ROLE..."
  umask 077
  wg genkey | tee "$PRIV_FILE" | wg pubkey > "$PUB_FILE"
  chmod 600 "$PRIV_FILE"
  chmod 644 "$PUB_FILE"
  chown root:root "$PRIV_FILE" "$PUB_FILE"
else
  echo "[*] Existing keypair found for $ROLE (not displayed for security)."
fi

# read public key for convenience (used to print to operator; private key not printed)
ROLE_PUB_KEY=$(cat "$PUB_FILE")

echo "[*] $ROLE public key (copy this to the concentrator peers as needed):"
echo "$ROLE_PUB_KEY"
echo "[*] (Keep the private key file at $PRIV_FILE secure.)"

# === write wg0.conf template (no PrivateKey embedded) ===
WG_CONF="$WG_DIR/wg0.conf"
UPLINK_IF=$(detect_uplink_iface)

if [[ "$ROLE" == "concentrator" ]]; then
  cat > "$WG_CONF" <<EOF
[Interface]
Address = ${LOCAL_WG_ADDR}
ListenPort = ${WG_LISTEN_PORT}
# private key loaded at PostUp; not present inline on disk
PostUp = wg set %i private-key ${PRIV_FILE}; sysctl -w net.ipv4.ip_forward=1; iptables -I FORWARD -i %i -j ACCEPT; iptables -I FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.44.0.0/24 -o ${UPLINK_IF} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.44.0.0/24 -o ${UPLINK_IF} -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; sysctl -w net.ipv4.ip_forward=0

# Peers: add [Peer] sections manually or via automation (public keys only)
# Example:
# [Peer]
# PublicKey = <redirector_public_key>
# AllowedIPs = 10.44.0.2/32

EOF

  # ensure UFW allows WireGuard port
  ufw allow "${WG_LISTEN_PORT}/udp"

elif [[ "$ROLE" == "redirector" ]]; then
  # redirector does not NAT; keep minimal forwarding rules if you want to allow incoming UDP on the wg port
  cat > "$WG_CONF" <<EOF
[Interface]
Address = ${LOCAL_WG_ADDR}
ListenPort = ${WG_LISTEN_PORT}
PostUp = wg set %i private-key ${PRIV_FILE}; iptables -I INPUT -p udp --dport ${WG_LISTEN_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${WG_LISTEN_PORT} -j ACCEPT

[Peer]
# Concentrator's public key and AllowedIPs MUST be added by operator:
# PublicKey = <concentrator_public_key>
# AllowedIPs = 10.44.0.1/32
# Endpoint = <concentrator_lan_or_public_ip>:51820
# PersistentKeepalive = 25

EOF

  # allow WireGuard UDP for outgoing NAT traversal if needed (not strictly required if redirector initiates)
  ufw allow "${WG_LISTEN_PORT}/udp"
fi

# secure file perms for config
chown root:root "$WG_CONF"
chmod 600 "$WG_CONF"

echo "[*] wg0.conf written to $WG_CONF (private key loaded via PostUp)."

# enable and start the wg-quick@wg0 service
echo "[*] Enabling and starting wg-quick@wg0..."
systemctl enable wg-quick@wg0
# attempt to start (idempotent)
set +e
systemctl restart wg-quick@wg0
WG_EXIT=$?
set -e
if [[ $WG_EXIT -ne 0 ]]; then
  echo "[!] Warning: wg-quick@wg0 restart returned exit code $WG_EXIT — check journalctl -u wg-quick@wg0"
fi

# === role-specific extras ===
if [[ "$ROLE" == "redirector" ]]; then
  echo "[*] Configuring nginx redirector skeleton (adjust proxy_pass manually)..."
  # default small nginx site (beacon proxy path /cdn)
  cat > /etc/nginx/sites-available/redirector <<'NGINX_EOF'
server {
    listen 80;
    server_name _;

    location /cdn {
        # Replace below with your internal C2 VPN IP:port (e.g., http://10.44.0.10:8888)
        proxy_pass http://10.44.0.50:8888;
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
    }
}
NGINX_EOF

  ln -sf /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/
  nginx -t && systemctl restart nginx || echo "[!] Nginx config test failed - check logs"
fi

# === Diagnostics ===
echo ""
echo "=== Diagnostics ==="
echo "[*] wg show output:"
wg show || true
echo ""
echo "[*] interface addresses (ip -4 addr show):"
ip -4 addr show || true
echo ""
echo "[*] listening UDP sockets (ss -unlp | grep -E '518|54156' || true):"
ss -unlp | egrep '51820|54156|wg' || true
echo ""
echo "[*] iptables (filter) summary:"
iptables -L -v -n || true
echo ""
echo "[*] iptables (nat) summary:"
iptables -t nat -L -v -n || true
echo ""
echo "[*] UFW status:"
ufw status verbose || true
echo ""

# Try simple pings to expected peer wg addresses (harmless if peer not up)
if [[ "$ROLE" == "concentrator" ]]; then
  echo "[*] Attempting ping to redirector wg IP (10.44.0.2) ..."
  ping -c 3 10.44.0.2 || echo "[!] ping to 10.44.0.2 failed (peer may be down)"
elif [[ "$ROLE" == "redirector" ]]; then
  echo "[*] Attempting ping to concentrator wg IP (10.44.0.1) ..."
  ping -c 3 10.44.0.1 || echo "[!] ping to 10.44.0.1 failed (peer may be down)"
fi

echo ""
echo "[*] Setup complete for role: $ROLE"
echo "[*] Next steps:"
echo "  - On the concentrator: add Redirector and Laptop [Peer] blocks (public keys + AllowedIPs /32) to /etc/wireguard/wg0.conf and restart wg-quick@wg0"
echo "  - On the redirector: populate the [Peer] section with the concentrator public key and Endpoint = <concentrator_lan_or_public_ip>:51820 then restart wg-quick@wg0"
echo "  - Use 'wg show' on each side to confirm latest-handshake timestamps."

exit 0
