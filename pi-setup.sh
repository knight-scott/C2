#!/bin/bash
# role_setup.sh - Harden Pi Zero 2 and configure based on role
# Usage: ./role_setup.sh <role>
# Roles: concentrator | redirector

set -euo pipefail

ROLE=${1:-""}
USER="ops"
SSH_DIR="/home/$USER/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

if [[ -z "$ROLE" ]]; then
    echo "Usage: $0 <concentrator|redirector>"
    exit 1
fi

echo "[*] Updating system..."
sudo apt update && sudo apt -y upgrade

echo "[*] Ensuring SSH permissions are correct..."
sudo chown -R $USER:$USER $SSH_DIR
sudo chmod 700 $SSH_DIR
sudo chmod 600 $AUTHORIZED_KEYS

echo "[*] Hardening SSH..."
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

echo "[*] Installing useful packages..."
sudo apt install -y ufw fail2ban vim git net-tools curl

echo "[*] Setting firewall defaults..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh

# ======================
# Role-specific configs
# ======================

if [[ "$ROLE" == "concentrator" ]]; then
    echo "[*] Configuring Concentrator (VPN Server)..."

    sudo apt install -y wireguard

    # Generate server keys if not already there
    WG_DIR="/etc/wireguard"
    if [[ ! -f "$WG_DIR/privatekey" ]]; then
        umask 077
        wg genkey | sudo tee $WG_DIR/privatekey | wg pubkey | sudo tee $WG_DIR/publickey
    fi

    SERVER_PRIV=$(sudo cat $WG_DIR/privatekey)
    SERVER_PUB=$(sudo cat $WG_DIR/publickey)

    # Basic WireGuard config
    WG_CONF="$WG_DIR/wg0.conf"
    if [[ ! -f "$WG_CONF" ]]; then
        cat <<EOF | sudo tee $WG_CONF
[Interface]
PrivateKey = $SERVER_PRIV
Address = 10.44.0.1/24
ListenPort = 51820

# Add peers manually later with [Peer] sections
EOF
    fi

    sudo chmod 600 $WG_CONF
    sudo systemctl enable wg-quick@wg0
    sudo systemctl start wg-quick@wg0

    sudo ufw allow 51820/udp
    echo "[*] WireGuard VPN setup complete. Use 'wg' to add peers."

elif [[ "$ROLE" == "redirector" ]]; then
    echo "[*] Configuring Redirector (Reverse Proxy)..."

    sudo apt install -y nginx

    # Default proxy config — forwards HTTPS traffic to C2 (adjust IP/port)
    cat <<EOF | sudo tee /etc/nginx/sites-available/redirector
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://10.0.0.50:8888; # <-- replace with actual C2 IP:port
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    sudo ln -sf /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl restart nginx

    # Harden UFW — only allow SSH and HTTP/HTTPS
    sudo ufw allow http
    sudo ufw allow https

    echo "[*] Redirector proxy setup complete. Adjust proxy_pass target for your C2."

else
    echo "[!] Unknown role: $ROLE"
    exit 1
fi

sudo ufw enable

echo "[*] Setup complete for role: $ROLE"
echo "[*] Reboot recommended."
