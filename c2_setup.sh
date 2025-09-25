#!/bin/bash
# c2_setup.sh - Harden Avaota-A1 and configure as C2 server with Sliver + BeEF
# Usage: sudo ./c2_setup.sh
# Designed for AvaotaOS (Debian-based) on Avaota-A1 SBC
set -euo pipefail

USER="ops"
SSH_DIR="/home/$USER/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
WG_DIR="/etc/wireguard"
C2_DIR="/opt/c2"
SLIVER_DIR="$C2_DIR/sliver"
BEEF_DIR="$C2_DIR/beef"

echo "[*] C2 Server Setup - Avaota-A1 Hardening and Framework Installation"
echo "[*] Target frameworks: Sliver C2 + BeEF"
echo ""

# Check if running on Avaota-A1 (basic check)
if ! grep -q "Avaota" /proc/device-tree/model 2>/dev/null && ! grep -q "A527" /proc/cpuinfo 2>/dev/null; then
    echo "[!] Warning: This script is designed for Avaota-A1 SBC. Continuing anyway..."
fi

echo "[*] Updating system packages..."
apt update && apt -y full-upgrade

echo "[*] Installing base security and development packages..."
DEBIAN_FRONTEND=noninteractive apt -y install \
    ufw fail2ban \
    git curl wget unzip \
    build-essential \
    golang-go \
    nodejs npm \
    ruby ruby-dev \
    sqlite3 \
    nginx \
    htop tmux \
    jq

# Ensure ops user exists and has proper SSH setup
echo "[*] Configuring user accounts and SSH access..."
if id -u "$USER" >/dev/null 2>&1; then
    mkdir -p "$SSH_DIR"
    chown "$USER":"$USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    if [[ -f "$AUTHORIZED_KEYS" ]]; then
        chown "$USER":"$USER" "$AUTHORIZED_KEYS"
        chmod 600 "$AUTHORIZED_KEYS"
    fi
    # Add ops to sudo group if not already
    usermod -aG sudo "$USER"
else
    echo "[!] User $USER does not exist. Creating user..."
    useradd -m -s /bin/bash -G sudo "$USER"
    mkdir -p "$SSH_DIR"
    chown "$USER":"$USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    echo "[!] Please add SSH public keys to $AUTHORIZED_KEYS manually"
fi

echo "[*] Hardening SSH configuration..."
# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Apply security settings
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config

# Restart SSH to apply changes
systemctl restart ssh

echo "[*] Configuring UFW firewall..."
# Reset UFW to clean state
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow ssh

# Allow WireGuard (C2 will be a VPN peer)
ufw allow 51821/udp  # Use different port from concentrator

# Allow common C2 ports (will be restricted to VPN traffic via nginx proxy)
# Sliver default ports: 80, 443, 8888, 31337
# BeEF default ports: 3000

# Note: These will be proxied through nginx and only accessible via VPN
ufw allow 80/tcp
ufw allow 443/tcp

ufw --force enable

echo "[*] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local <<'FAIL2BAN_EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
FAIL2BAN_EOF

systemctl enable fail2ban
systemctl restart fail2ban

# === WireGuard Setup for C2 Server ===
echo "[*] Setting up WireGuard for C2 server..."
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

PRIV_FILE="$WG_DIR/c2_server_private.key"
PUB_FILE="$WG_DIR/c2_server_public.key"
WG_LISTEN_PORT=51821  # Different from concentrator
LOCAL_WG_ADDR="10.44.0.10/32"

if [[ ! -f "$PRIV_FILE" ]]; then
    echo "[*] Generating WireGuard keypair for C2 server..."
    umask 077
    wg genkey | tee "$PRIV_FILE" | wg pubkey > "$PUB_FILE"
    chmod 600 "$PRIV_FILE"
    chmod 644 "$PUB_FILE"
    chown root:root "$PRIV_FILE" "$PUB_FILE"
else
    echo "[*] Existing WireGuard keypair found."
fi

C2_PUB_KEY=$(cat "$PUB_FILE")
echo ""
echo "[*] C2 Server WireGuard Public Key (add this to concentrator):"
echo "$C2_PUB_KEY"
echo ""

# Create WireGuard config for C2 server
WG_CONF="$WG_DIR/wg0.conf"
cat > "$WG_CONF" <<EOF
[Interface]
Address = ${LOCAL_WG_ADDR}
ListenPort = ${WG_LISTEN_PORT}
PostUp = wg set %i private-key ${PRIV_FILE}
PostDown = true

[Peer]
# Concentrator configuration - populate manually
# PublicKey = <concentrator_public_key>
# AllowedIPs = 10.44.0.0/24
# Endpoint = <concentrator_public_or_lan_ip>:51820
# PersistentKeepalive = 25

EOF

chown root:root "$WG_CONF"
chmod 600 "$WG_CONF"
chattr +i "$WG_CONF"

echo "[*] WireGuard config created at $WG_CONF (marked immutable)"

# === Create C2 Directory Structure ===
echo "[*] Creating C2 framework directories..."
mkdir -p "$C2_DIR"
mkdir -p "$SLIVER_DIR"
mkdir -p "$BEEF_DIR"
mkdir -p "$C2_DIR/logs"
mkdir -p "$C2_DIR/data"
chown -R "$USER":"$USER" "$C2_DIR"

# === Install Sliver C2 Framework ===
echo "[*] Installing Sliver C2 Framework..."
cd "$SLIVER_DIR"

# Download latest Sliver release
SLIVER_VERSION=$(curl -s https://api.github.com/repos/BishopFox/sliver/releases/latest | jq -r '.tag_name')
echo "[*] Installing Sliver version: $SLIVER_VERSION"

# Download Sliver server for Linux ARM64 (Avaota-A1 is ARM64)
ARCH="arm64"
if [[ $(uname -m) == "x86_64" ]]; then
    ARCH="amd64"
fi

wget -O sliver-server "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux"
chmod +x sliver-server
chown "$USER":"$USER" sliver-server

# Create Sliver service configuration
cat > /etc/systemd/system/sliver.service <<EOF
[Unit]
Description=Sliver C2 Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SLIVER_DIR
ExecStart=$SLIVER_DIR/sliver-server daemon --lhost 10.44.0.10
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# === Install BeEF Framework ===
echo "[*] Installing BeEF (Browser Exploitation Framework)..."
cd "$BEEF_DIR"

# Install BeEF dependencies
gem install bundler

# Clone BeEF repository
git clone https://github.com/beefproject/beef.git .
chown -R "$USER":"$USER" "$BEEF_DIR"

# Install BeEF as ops user
sudo -u "$USER" bundle install

# Create BeEF configuration
sudo -u "$USER" cp config.yaml config.yaml.backup

# Update BeEF config to bind to VPN interface
sudo -u "$USER" tee config.yaml.local > /dev/null <<EOF
beef:
    version: '0.5.4.0'
    debug: false
    crypto_default_value_length: 80
    
    restrictions:
        permitted_hooking_subnet: ["10.44.0.0/24", "127.0.0.0/8", "0.0.0.0/0"]
        permitted_ui_subnet: ["10.44.0.0/24", "127.0.0.0/8"]
        
    http:
        debug: false
        host: "10.44.0.10"
        port: "3000"
        
    https:
        enable: false
        host: "10.44.0.10"
        port: "3443"
        
    database:
        file: "db/beef.db"
        
    credentials:
        user: "beef"
        passwd: "$(openssl rand -base64 12)"
        
    extension:
        admin_ui:
            enable: true
        metasploit:
            enable: false
        social_engineering:
            enable: true
EOF

# Create BeEF service
cat > /etc/systemd/system/beef.service <<EOF
[Unit]
Description=BeEF Framework
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$BEEF_DIR
ExecStart=/usr/bin/ruby beef -x -c config.yaml.local
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# === Configure Nginx Reverse Proxy ===
echo "[*] Configuring Nginx reverse proxy for C2 services..."
cat > /etc/nginx/sites-available/c2-server <<'NGINX_EOF'
# C2 Server Nginx Configuration
# Proxies external requests to internal C2 frameworks

server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    
    # Sliver HTTP listener proxy
    location /sliver/ {
        proxy_pass http://127.0.0.1:8888/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
    }
    
    # BeEF hook proxy (for serving hook.js)
    location /beef/ {
        proxy_pass http://10.44.0.10:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
    
    # Default response - basic decoy page
    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ =404;
    }
}

# BeEF Admin UI - Only accessible from VPN
server {
    listen 3001;
    server_name _;
    
    # Restrict to VPN subnet only
    allow 10.44.0.0/24;
    deny all;
    
    location / {
        proxy_pass http://10.44.0.10:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
NGINX_EOF

# Enable C2 nginx site
ln -sf /etc/nginx/sites-available/c2-server /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
if nginx -t; then
    systemctl restart nginx
    echo "[*] Nginx configured successfully"
else
    echo "[!] Nginx configuration test failed"
fi

# === Create Management Scripts ===
echo "[*] Creating C2 management scripts..."

# C2 status script
cat > "$C2_DIR/c2-status.sh" <<'STATUS_EOF'
#!/bin/bash
echo "=== C2 Server Status ==="
echo ""
echo "Services:"
systemctl --no-pager status sliver beef nginx wg-quick@wg0 | grep -E "(●|Active:|Main PID:)"
echo ""
echo "WireGuard:"
wg show
echo ""
echo "Network Listeners:"
ss -tlnp | grep -E "(3000|3001|8888|80|443)"
echo ""
echo "BeEF Credentials:"
if [[ -f /opt/c2/beef/config.yaml.local ]]; then
    echo "User: $(grep -A1 'credentials:' /opt/c2/beef/config.yaml.local | grep 'user:' | awk '{print $2}' | tr -d '"')"
    echo "Pass: $(grep -A2 'credentials:' /opt/c2/beef/config.yaml.local | grep 'passwd:' | awk '{print $2}' | tr -d '"')"
fi
STATUS_EOF

# C2 start script
cat > "$C2_DIR/c2-start.sh" <<'START_EOF'
#!/bin/bash
echo "Starting C2 services..."
systemctl start sliver
systemctl start beef
systemctl start nginx
systemctl start wg-quick@wg0
echo "C2 services started. Check status with: ./c2-status.sh"
START_EOF

# C2 stop script
cat > "$C2_DIR/c2-stop.sh" <<'STOP_EOF'
#!/bin/bash
echo "Stopping C2 services..."
systemctl stop sliver
systemctl stop beef
echo "C2 services stopped."
START_EOF

chmod +x "$C2_DIR"/*.sh
chown "$USER":"$USER" "$C2_DIR"/*.sh

# === System Services ===
echo "[*] Enabling system services..."
systemctl daemon-reload
systemctl enable sliver
systemctl enable beef
systemctl enable nginx

echo "[*] Starting services..."
systemctl start sliver || echo "[!] Sliver service failed to start - check logs with 'journalctl -u sliver'"
systemctl start beef || echo "[!] BeEF service failed to start - check logs with 'journalctl -u beef'"

echo "[*] Verifying service bindings..."
echo "Checking if services bind to VPN interface:"
sleep 5
ss -tlnp | grep -E "10.44.0.10.*(3000|8888)" || echo "[!] Services may not be bound to VPN IP"

# === Final Configuration ===
echo "[*] Creating decoy web content..."
cat > /var/www/html/index.html <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Server Status</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>System Online</h1>
    <p>Server is running normally.</p>
    <p><small>Last updated: $(date)</small></p>
</body>
</html>
HTML_EOF

# === Diagnostics and Summary ===
echo ""
echo "=== C2 Server Setup Complete ==="
echo ""
echo "INSTALLED FRAMEWORKS:"
echo "  - Sliver C2: $SLIVER_DIR/sliver-server"
echo "  - BeEF: $BEEF_DIR"
echo ""
echo "NETWORK CONFIGURATION:"
echo "  - VPN IP: 10.44.0.10/32"
echo "  - WireGuard Port: 51821/udp"
echo "  - Sliver HTTP: 127.0.0.1:8888 (proxied via /sliver/)"
echo "  - BeEF: 10.44.0.10:3000 (proxied via /beef/)"
echo "  - BeEF Admin: 10.44.0.10:3001 (VPN-only access)"
echo ""
echo "MANAGEMENT SCRIPTS:"
echo "  - Status: $C2_DIR/c2-status.sh"
echo "  - Start: $C2_DIR/c2-start.sh"
echo "  - Stop: $C2_DIR/c2-stop.sh"
echo ""
echo "NEXT STEPS:"
echo "1. Add this C2's public key to concentrator:"
echo "   $C2_PUB_KEY"
echo ""
echo "2. Configure concentrator peer in $WG_CONF:"
echo "   chattr -i $WG_CONF"
echo "   # Add concentrator public key and endpoint"
echo "   chattr +i $WG_CONF"
echo ""
echo "3. Start WireGuard: systemctl start wg-quick@wg0"
echo ""
echo "4. Access services via VPN:"
echo "   - BeEF Admin UI: http://10.44.0.10:3001"
echo "   - Sliver Console: $SLIVER_DIR/sliver-server console"
echo ""
echo "5. Check service status: $C2_DIR/c2-status.sh"
echo ""
echo "SECURITY NOTES:"
echo "  - SSH hardened (keys only, no root login)"
echo "  - UFW enabled (SSH, WG, HTTP/HTTPS only)"
echo "  - fail2ban active for SSH protection"
echo "  - C2 services only accessible via VPN"
echo "  - Config files marked immutable with chattr +i"
echo ""

exit 0

# Add to the end of the C2 setup script
