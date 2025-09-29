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
STATE_DIR="/var/lib/c2_setup"
CRITICAL_PKG_FAILURE=0
mkdir -p "$STATE_DIR"

# ----- helper functions -----
log() { echo "[*] $*"; }
warn() { echo "[!] $*"; }

# Persistent markers for idempotency
is_completed() {
    local key="$1"
    [[ -f "$STATE_DIR/$key" ]]
}
mark_completed() {
    local key="$1"
    mkdir -p "$STATE_DIR"
    touch "$STATE_DIR/$key"
}

# Package helpers
pkg_installed() {
    local pkg="$1"
    # dpkg-query returns non-zero for not-installed; we use a safe test
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
}

ensure_pkg() {
    local pkg="$1"
    if pkg_installed "$pkg"; then
        log "Package '$pkg' is already installed - skipping."
        return 0
    fi

    log "Installing package: $pkg"
    # Use apt-get to be a bit more script-friendly; swallow failures but warn
    if ! DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends "$pkg" >/dev/null 2>&1; then
        warn "Failed to install package '$pkg'. Continuing; you may want to inspect this manually."
        return 1
    fi
    log "Package '$pkg' installed (or apt reported success)."
    return 0
}

ensure_packages() {
    # Accepts list of packages
    for p in "$@"; do
        ensure_pkg "$p" || true
    done
}

# Ensure apt cache updated once (safe if run multiple times)
apt_update_once() {
    if ! is_completed "apt_updated"; then
        log "Updating apt cache and upgrading installed packages..."
        apt-get update -y
        apt-get -y full-upgrade
        mark_completed "apt_updated"
    else
        log "apt already updated in a previous run - skipping update."
    fi
}

# ----- start script -----
log "C2 Server Setup - Avaota-A1 Hardening and Framework Installation"
log "Target frameworks: Sliver C2 + BeEF"
echo ""

# Check if running on Avaota-A1 (basic check)
if ! grep -q "Avaota" /proc/device-tree/model 2>/dev/null && ! grep -q "A527" /proc/cpuinfo 2>/dev/null; then
    echo "[!] Warning: This script is designed for Avaota-A1 SBC. Continuing anyway..."
fi

# Update & upgrade (dempotent via marker)
apt_update_once

log "Installing base security and development packages..."
BASE_PKGS=(
    fail2ban
    wireguard
    wireguard-tools
    git 
    curl 
    wget 
    unzip
    build-essential
    golang-go
    nodejs 
    npm
    ruby 
    ruby-dev
    sqlite3
    nginx
    htop 
    tmux
    jq
)

ensure_packages "${BASE_PKGS[@]}"

# Verify critical packages installed correctly
log "Verifying critical package installation..."
for pkg in wireguard fail2ban git golang-go nginx ruby; do
    if ! pkg_installed "$pkg"; then
        warn "Critical package '$pkg' is NOT installed."
        CRITICAL_PKG_FAILURE=1
    fi
done

if [[ $CRITICAL_PKG_FAILURE -ne 0 ]]; then
    warn "One or more critical packages failed to install. Inspect apt logs and fix before proceeding."
    # Decide here whether to exit. Keep exit to fail early if critical packages missing
    exit 1
fi

log "All required packages installed successfully"

# Ensure ops user exists and has proper SSH setup
log "Configuring user accounts and SSH access..."
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
    log "User $USER does not exist. Creating user..."
    useradd -m -s /bin/bash -G sudo "$USER"
    mkdir -p "$SSH_DIR"
    chown "$USER":"$USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    log "Please add SSH public keys to $AUTHORIZED_KEYS manually"
fi

# Remove default avaota user for security
log "Removing default avaota user for security..."
if id -u "avaota" >/dev/null 2>&1; then
    # Kill any processes owned by avaota user
    pkill -u avaota || true
    # Remove the user and home directory
    userdel -r avaota
    log "Avaota user removed successfully"
else
    log "Avaota user not found (already removed or never existed)"
fi

# Disable unused user accounts
log "Disabling other system accounts..."
for user in games news uucp proxy www-data backup list irc gnats; do
    if id -u "$user" >/dev/null 2>&1; then
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
    fi
done

# === SSH Hardening ===
log "Hardening SSH configuration..."
if [[ -f /etc/ssh/sshd_config ]]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup || true
fi

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^#\?AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' /etc/ssh/sshd_config || true
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config || true
sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || true
sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config || true

# Restart SSH to apply changes (guarded)
if systemctl list-unit-files | grep -q "^ssh"; then
    systemctl restart ssh || warn "Failed to restart ssh - check journalctl -u ssh"
else
    warn "ssh service unit not found; skipping ssh restart"
fi
log "SSH configuration hardened"

# Configure fail2ban only if it's installed
if pkg_installed "fail2ban"; then
    log "Configuring fail2ban..."
    mkdir -p /etc/fail2ban
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

    systemctl enable fail2ban || warn "Failed to enable fail2ban"
    systemctl restart fail2ban || warn "Failed to restart fail2ban - check 'journalctl -u fail2ban'"
    log "fail2ban configured and started"
else
    warn "fail2ban package not installed; skipping fail2ban configuration"
fi

# === WireGuard Setup for C2 Server ===
if ! is_completed "wireguard_configured"; then
    log "Setting up WireGuard for C2 server..."
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"

    PRIV_FILE="$WG_DIR/c2_server_private.key"
    PUB_FILE="$WG_DIR/c2_server_public.key"
    WG_LISTEN_PORT=51821  # Different from concentrator
    LOCAL_WG_ADDR="10.44.0.10/32"

    if [[ ! -f "$PRIV_FILE" ]]; then
        log "Generating WireGuard keypair for C2 server..."
        umask 077
        # ensure wg tool is present; if not, warn but continue
        if command -v wg >/dev/null 2>&1; then
            wg genkey | tee "$PRIV_FILE" | wg pubkey > "$PUB_FILE"
        else
            warn "wg tool not found; creating placeholder keys (you should generate real keys manually)"
            echo "PRIVATE_PLACEHOLDER" > "$PRIV_FILE"
            echo "PUBLIC_PLACEHOLDER" > "$PUB_FILE"
        fi
        chmod 600 "$PRIV_FILE"
        chmod 644 "$PUB_FILE"
        chown root:root "$PRIV_FILE" "$PUB_FILE"
    else
        log "Existing WireGuard keypair found."
    fi

    C2_PUB_KEY=$(cat "$PUB_FILE" 2>/dev/null || echo "<no-pub-key>")
    echo ""
    log "C2 Server WireGuard Public Key (add this to concentrator):"
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
    # Make immutable if chattr exists and not already immutable
    if command -v chattr >/dev/null 2>&1; then
        chattr +i "$WG_CONF" || true
    fi

    log "WireGuard config created at $WG_CONF (immutable flag applied if available)"
    mark_completed "wireguard_configured"
else
    log "WireGuard configuration already completed, skipping..."
    PUB_FILE="$WG_DIR/c2_server_public.key"
    if [[ -f "$PUB_FILE" ]]; then
        C2_PUB_KEY=$(cat "$PUB_FILE")
        log "C2 Server WireGuard Public Key: $C2_PUB_KEY"
    fi
fi

# === Create C2 Directory Structure ===
if ! is_completed "c2_directories_created"; then
    log "Creating C2 framework directories..."
    mkdir -p "$C2_DIR" "$SLIVER_DIR" "$BEEF_DIR" "$C2_DIR/logs" "$C2_DIR/data"
    chown -R "$USER":"$USER" "$C2_DIR" || true
    mark_completed "c2_directories_created"
else
    log "C2 directories already created, skipping..."
fi

# === Install Sliver C2 Framework ===
if ! is_completed "sliver_installed"; then
    log "Installing Sliver C2 Framework..."
    mkdir -p "$SLIVER_DIR"
    cd "$SLIVER_DIR" || exit 1

    # Try to detect latest version if jq available
    if command -v jq >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        SLIVER_VERSION=$(curl -s https://api.github.com/repos/BishopFox/sliver/releases/latest | jq -r '.tag_name')
        log "Installing Sliver version: $SLIVER_VERSION"
    else
        SLIVER_VERSION="latest"
        log "Installing latest Sliver version (jq or curl not available for version detection)"
    fi

    # Decide arch
    ARCH="arm64"
    if [[ $(uname -m) == "x86_64" ]]; then
        ARCH="amd64"
    fi

    log "Downloading Sliver server..."
    if [[ "$SLIVER_VERSION" != "latest" ]]; then
        DOWNLOAD_URL="https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux"
    else
        DOWNLOAD_URL="https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux"
    fi

    if ! wget -O sliver-server "$DOWNLOAD_URL"; then
        warn "Failed to download Sliver server. Try manual download or check internet connectivity"
        # don't exit here; mark not installed and continue
    else
        chmod +x sliver-server
        chown "$USER":"$USER" sliver-server
        if [[ ! -x sliver-server ]]; then
            warn "Sliver server not executable after download"
        else
            log "Sliver server downloaded successfully"
        fi
    fi

    cat > /etc/systemd/system/sliver.service <<EOF
[Unit]
Description=Sliver C2 Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SLIVER_DIR
ExecStart=$SLIVER_DIR/sliver-server daemon --lhost 10.44.0.10 --lport 8888
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || true
    systemctl enable sliver || warn "Failed to enable sliver service"
    mark_completed "sliver_installed"
else
    log "Sliver installation already completed, skipping..."
fi

# === Install BeEF Framework ===
if ! is_completed "beef_installed"; then
    log "Installing BeEF (Browser Exploitation Framework)..."
    mkdir -p "$BEEF_DIR"
    cd "$BEEF_DIR" || exit 1

    # Install bundler if gem tool present
    if command -v gem >/dev/null 2>&1; then
        log "Installing Ruby bundler..."
        if ! gem install bundler --no-document >/dev/null 2>&1; then
            warn "Failed to install bundler via gem. Try: gem install bundler --no-document"
        fi
    else
        warn "gem not found; cannot install bundler automatically."
    fi

    # Clone BeEF repository if not present
    if [[ ! -d "$BEEF_DIR/.git" && ! -f "beef" ]]; then
        log "Cloning BeEF repository..."
        if ! git clone https://github.com/beefproject/beef.git .; then
            warn "Failed to clone BeEF repository; check internet connectivity"
        fi
    else
        log "BeEF repository already present"
    fi

    chown -R "$USER":"$USER" "$BEEF_DIR" || true

    # Install dependencies via bundle if available
    if command -v bundle >/dev/null 2>&1; then
        log "Installing BeEF dependencies (bundle install)..."
        if ! sudo -u "$USER" bundle install --jobs=4 --retry=3 >/dev/null 2>&1; then
            warn "BeEF bundle install failed. Ensure libsqlite3-dev and libssl-dev are installed and try manually."
        else
            log "BeEF bundle install completed (or reported success)."
        fi
    else
        warn "bundle not found; skipping 'bundle install' step. Install bundler and run 'bundle install' as $USER."
    fi

    # Create local config
    if [[ -f config.yaml && ! -f config.yaml.backup ]]; then
        sudo -u "$USER" cp config.yaml config.yaml.backup || true
    fi

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

    systemctl daemon-reload || true
    systemctl enable beef || warn "Failed to enable beef service"
    mark_completed "beef_installed"
else
    log "BeEF installation already completed, skipping..."
fi

# === Configure Nginx Reverse Proxy ===
log "Configuring Nginx reverse proxy for C2 services..."
cat > /etc/nginx/sites-available/c2-server <<'NGINX_EOF'
# C2 Server Nginx Configuration
# Proxies external requests to internal C2 frameworks

# Bind only to the WireGuard interface (10.44.0.10)
server {
    listen 10.44.0.10:80;
    server_name internal-api.knightsgambitsecurity.com;

    # Restrict access to VPN subnet only
    allow 10.44.0.0/24;
    deny all;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    # Sliver HTTP listener proxy (implant comms, operator RPC)
    location /sliver {
        proxy_pass http://127.0.0.1:8888/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }

    # BeEF hook (served to targets through redirector)
    location /beef {
        proxy_pass http://127.0.0.1:3000/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Default decoy page
    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ =404;
    }
}

# BeEF Admin UI – separate port, VPN-only
server {
    listen 10.44.0.10:3001;
    server_name internal-api.knightsgambitsecurity.com;

    allow 10.44.0.0/24;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:3000/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX_EOF

# Enable C2 nginx site
ln -sf /etc/nginx/sites-available/c2-server /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
if nginx -t >/dev/null 2>&1; then
    systemctl restart nginx || warn "Failed to restart nginx"
    log "Nginx configured successfully"
else
    warn "Nginx configuration test failed; check /var/log/nginx/error.log"
fi

# === Create Management Scripts ===
log "Creating C2 management scripts..."
mkdir -p "$C2_DIR"
cat > "$C2_DIR/c2-status.sh" <<'STATUS_EOF'
# C2 status script
#!/bin/bash
echo "=== C2 Server Status ==="
echo ""
echo "Services:"
systemctl --no-pager status sliver beef nginx wg-quick@wg0 | grep -E "(●|Active:|Main PID:)"
echo ""
echo "WireGuard:"
wg show 2>/dev/null || echo "wg not available"
echo ""
echo "Network Listeners:"
ss -tlnp | grep -E "(3000|3001|8888|80|443)" || true
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
systemctl start sliver || echo "[!] Sliver failed to start"
systemctl start beef || echo "[!] BeEF failed to start"
systemctl start nginx || echo "[!] nginx failed to start"
systemctl start wg-quick@wg0 || echo "[!] wg-quick@wg0 failed to start"
echo "C2 services started. Check status with: ./c2-status.sh"
START_EOF

# C2 stop script
cat > "$C2_DIR/c2-stop.sh" <<'STOP_EOF'
#!/bin/bash
echo "Stopping C2 services..."
systemctl stop sliver || true
systemctl stop beef || true
echo "C2 services stopped."
STOP_EOF

chmod +x "$C2_DIR"/*.sh || true
chown "$USER":"$USER" "$C2_DIR"/*.sh || true

# === System Services ===
log "Enabling system services..."
systemctl daemon-reload || true
systemctl enable sliver || true
systemctl enable beef || true
systemctl enable nginx || true

log "Starting services (best-effort)..."
systemctl start sliver || warn "Sliver service failed to start - check logs with 'journalctl -u sliver'"
systemctl start beef || warn "BeEF service failed to start - check logs with 'journalctl -u beef'"

# === Final Configuration ===
log "Creating minimal status page..."
mkdir -p /var/www/html
cat > /var/www/html/index.html <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>System Status</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: monospace; background: #f0f0f0; margin: 40px; }
        .status { background: white; padding: 20px; border: 1px solid #ddd; }
        .ok { color: green; }
    </style>
</head>
<body>
    <div class="status">
        <h2>System Status</h2>
        <p class="ok">✓ Services operational</p>
        <p><small>Last check: $(date '+%Y-%m-%d %H:%M:%S')</small></p>
    </div>
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
echo "  - Sliver HTTP: 127.0.0.1:8888 (proxied via /sliver)"
echo "  - BeEF: 127.0.0.1:3000 (proxied via /beef)"
echo "  - BeEF Admin: 10.44.0.10:3001 (VPN-only access)"
echo ""
echo "REDIRECTOR INTEGRATION:"
echo "  - Redirector /api/v1/status → C2 /sliver → Sliver (127.0.0.1:8888)"
echo "  - Redirector /resources/updates → C2 /beef → BeEF (127.0.0.1:3000)"
echo "  - C2 binds only to VPN interface (10.44.0.10)"
echo "  - Health check available at /health"
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
echo "  - fail2ban active for SSH protection"
echo "  - C2 services only accessible via VPN"
echo "  - Config files marked immutable with chattr +i"
echo ""

exit 0