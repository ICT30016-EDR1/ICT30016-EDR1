#!/bin/bash

set -e

# ============================================================
# Juice Shop Injection Detection
# Full installation script
#
# Installs:
#   - Dependencies
#   - Wazuh Manager
#   - OWASP Juice Shop
#   - Juice Shop systemd service
#   - Juice Shop security telemetry
#   - Wazuh injection detection rules
#   - Wazuh Active Response
#
# Detection:
#   - SQL Injection
#   - SQLi Authentication Bypass
#   - XSS
#   - Command Injection
#   - SSTI
# ============================================================

JUICE_DIR="/home/juice/juice-shop"
JUICE_USER="juice"

WAZUH_DIR="/var/ossec"
RULE_FILE="$WAZUH_DIR/etc/rules/local_rules.xml"
AR_DIR="$WAZUH_DIR/active-response/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo " OWASP Juice Shop + Wazuh Injection Detection Installer"
echo "============================================================"

# ------------------------------------------------------------
# Check root
# ------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo
    echo "ERROR: Please run this script with sudo."
    echo
    echo "Example:"
    echo "  sudo ./install.sh"
    exit 1
fi

# ------------------------------------------------------------
# Check operating system
# ------------------------------------------------------------

if [ ! -f /etc/os-release ]; then
    echo "ERROR: Cannot determine operating system."
    exit 1
fi

. /etc/os-release

echo
echo "Operating system: $PRETTY_NAME"

if [ "$ID" != "ubuntu" ] && [ "$ID" != "debian" ]; then
    echo
    echo "WARNING: This installer is designed for Ubuntu/Debian."
    echo
    read -p "Continue anyway? [y/N]: " ANSWER

    if [[ ! "$ANSWER" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ------------------------------------------------------------
# Update system
# ------------------------------------------------------------

echo
echo "[1/12] Updating system packages..."

apt-get update
apt-get upgrade -y

# ------------------------------------------------------------
# Install basic dependencies
# ------------------------------------------------------------

echo
echo "[2/12] Installing dependencies..."

apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    python3 \
    python3-pip \
    build-essential \
    ca-certificates \
    gnupg \
    apt-transport-https \
    lsb-release \
    iptables

# ------------------------------------------------------------
# Install Node.js
# ------------------------------------------------------------

echo
echo "[3/12] Installing Node.js..."

if command -v node >/dev/null 2>&1; then
    echo "Node.js already installed:"
    node --version
else

    curl -fsSL https://deb.nodesource.com/setup_24.x | bash -

    apt-get install -y nodejs

fi

echo
echo "Node.js version:"
node --version

echo
echo "npm version:"
npm --version

# ------------------------------------------------------------
# Create Juice Shop user
# ------------------------------------------------------------

echo
echo "[4/12] Creating Juice Shop user..."

if id "$JUICE_USER" >/dev/null 2>&1; then
    echo "User '$JUICE_USER' already exists."
else
    useradd \
        --system \
        --create-home \
        --home-dir /home/juice \
        --shell /bin/bash \
        "$JUICE_USER"

    echo "Created user '$JUICE_USER'."
fi

# ------------------------------------------------------------
# Install Juice Shop
# ------------------------------------------------------------

echo
echo "[5/12] Installing OWASP Juice Shop..."

if [ -d "$JUICE_DIR/.git" ]; then

    echo "Juice Shop repository already exists."

else

    mkdir -p /home/juice

    git clone \
        --depth 1 \
        https://github.com/juice-shop/juice-shop.git \
        "$JUICE_DIR"

fi

chown -R "$JUICE_USER:$JUICE_USER" /home/juice

echo
echo "Installing Juice Shop dependencies..."

cd "$JUICE_DIR"

sudo -u "$JUICE_USER" npm install

# ------------------------------------------------------------
# Create Juice Shop logs
# ------------------------------------------------------------

echo
echo "[6/12] Creating Juice Shop logging..."

mkdir -p "$JUICE_DIR/logs"

touch "$JUICE_DIR/logs/security.log"

chown -R "$JUICE_USER:$JUICE_USER" "$JUICE_DIR/logs"

chmod 750 "$JUICE_DIR/logs"
chmod 640 "$JUICE_DIR/logs/security.log"

# ------------------------------------------------------------
# Install login telemetry
# ------------------------------------------------------------

echo
echo "[7/12] Installing Juice Shop security telemetry..."

LOGIN_FILE="$JUICE_DIR/routes/login.ts"

if [ ! -f "$LOGIN_FILE" ]; then
    echo "ERROR: Could not find:"
    echo "$LOGIN_FILE"
    exit 1
fi

# Make a backup
cp "$LOGIN_FILE" "$LOGIN_FILE.before-injection-detection"

python3 <<'PY'
from pathlib import Path

login_file = Path("/home/juice/juice-shop/routes/login.ts")

text = login_file.read_text()

# Add fs import
if "import fs from 'fs'" not in text:
    text = "import fs from 'fs'\n" + text

# Add telemetry function
telemetry = r'''

function logLoginEvent (req: Request, status: number) {
  const event = {
    event: 'login',
    srcip: req.ip,
    method: req.method,
    path: req.path,
    email: req.body?.email || '',
    status
  }

  fs.appendFileSync(
    '/home/juice/juice-shop/logs/security.log',
    JSON.stringify(event) + '\n'
  )
}
'''

if "function logLoginEvent" not in text:

    marker = "const login = async"

    if marker in text:
        text = text.replace(marker, telemetry + "\n" + marker)
    else:
        raise SystemExit(
            "Could not find login function in routes/login.ts"
        )

# Add telemetry to responses
# Only modify if it has not already been installed.
if "logLoginEvent(req, 401)" not in text:

    text = text.replace(
        "return res.status(401)",
        "logLoginEvent(req, 401)\n      return res.status(401)"
    )

if "logLoginEvent(req, 200)" not in text:

    text = text.replace(
        "return res.status(200)",
        "logLoginEvent(req, 200)\n      return res.status(200)"
    )

login_file.write_text(text)

PY

# ------------------------------------------------------------
# Compile Juice Shop
# ------------------------------------------------------------

echo
echo "Compiling Juice Shop..."

cd "$JUICE_DIR"

sudo -u "$JUICE_USER" npm run build:server

# ------------------------------------------------------------
# Create Juice Shop systemd service
# ------------------------------------------------------------

echo
echo "[8/12] Creating Juice Shop systemd service..."

cat > /etc/systemd/system/juice-shop.service <<'EOF'
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
Type=simple
User=juice
WorkingDirectory=/home/juice/juice-shop
ExecStart=/usr/bin/node build/app
Restart=on-failure
Environment=NODE_ENV=production
Environment=HOST=0.0.0.0
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

systemctl enable juice-shop

systemctl restart juice-shop

sleep 5

if systemctl is-active --quiet juice-shop; then
    echo "Juice Shop is running."
else
    echo
    echo "ERROR: Juice Shop failed to start."
    systemctl status juice-shop --no-pager
    exit 1
fi

# ------------------------------------------------------------
# Install Wazuh
# ------------------------------------------------------------

echo
echo "[9/12] Installing Wazuh Manager..."

if [ -d "$WAZUH_DIR" ]; then

    echo "Wazuh installation already exists."

else

    cd /root

    curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh

    chmod +x wazuh-install.sh

    echo
    echo "Installing Wazuh Manager..."
    echo

    ./wazuh-install.sh --wazuh-server wazuh-1

fi

# ------------------------------------------------------------
# Install Wazuh rules
# ------------------------------------------------------------

echo
echo "[10/12] Installing Wazuh injection detection..."

if [ ! -d "$WAZUH_DIR" ]; then
    echo "ERROR: Wazuh installation directory not found."
    exit 1
fi

mkdir -p "$AR_DIR"

# Backup existing rules
if [ -f "$RULE_FILE" ]; then

    cp "$RULE_FILE" \
       "$RULE_FILE.before-injection-detection"

fi

# Install project rules
if [ ! -f "$SCRIPT_DIR/wazuh/local_rules.xml" ]; then

    echo
    echo "ERROR:"
    echo "Project Wazuh rules were not found:"
    echo "$SCRIPT_DIR/wazuh/local_rules.xml"
    exit 1

fi

cp \
    "$SCRIPT_DIR/wazuh/local_rules.xml" \
    "$RULE_FILE"

chown root:wazuh "$RULE_FILE"
chmod 660 "$RULE_FILE"

# ------------------------------------------------------------
# Install Active Response
# ------------------------------------------------------------

echo
echo "Installing Active Response..."

if [ ! -f "$SCRIPT_DIR/wazuh/injection-block.py" ]; then

    echo
    echo "ERROR:"
    echo "Active Response script was not found:"
    echo "$SCRIPT_DIR/wazuh/injection-block.py"
    exit 1

fi

cp \
    "$SCRIPT_DIR/wazuh/injection-block.py" \
    "$AR_DIR/injection-block.py"

chmod 750 "$AR_DIR/injection-block.py"
chown root:wazuh "$AR_DIR/injection-block.py"

# ------------------------------------------------------------
# Configure Wazuh
# ------------------------------------------------------------

echo
echo "[11/12] Configuring Wazuh..."

OSSEC="$WAZUH_DIR/etc/ossec.conf"

cp "$OSSEC" "$OSSEC.before-injection-detection"

python3 <<'PY'
from pathlib import Path

config = Path("/var/ossec/etc/ossec.conf")

text = config.read_text()

access_log = """
    <!-- OWASP Juice Shop access log -->
    <localfile>
      <location>/home/juice/juice-shop/logs/access.log.%Y-%m-%d</location>
      <log_format>apache</log_format>
    </localfile>
"""

security_log = """
    <!-- OWASP Juice Shop security telemetry -->
    <localfile>
      <location>/home/juice/juice-shop/logs/security.log</location>
      <log_format>json</log_format>
    </localfile>
"""

command = """
    <!-- Injection Active Response -->
    <command>
      <name>injection-block</name>
      <executable>injection-block.py</executable>
      <timeout_allowed>yes</timeout_allowed>
    </command>
"""

active_response = """
    <!-- Automatically block high-confidence injection attacks -->
    <active-response>
      <disabled>no</disabled>
      <command>injection-block</command>
      <location>server</location>
      <rules_id>100101,100106,100111,100121,100131</rules_id>
      <timeout>60</timeout>
    </active-response>
"""

items = [
    access_log,
    security_log,
    command,
    active_response
]

for item in items:
    if item.strip() not in text:
        text = text.replace(
            "</ossec_config>",
            item + "\n</ossec_config>"
        )

config.write_text(text)

PY

# ------------------------------------------------------------
# Create incident logs
# ------------------------------------------------------------

touch "$WAZUH_DIR/logs/injection-incidents.log"
touch "$WAZUH_DIR/logs/injection-response.log"

chown wazuh:wazuh \
    "$WAZUH_DIR/logs/injection-incidents.log" \
    "$WAZUH_DIR/logs/injection-response.log"

chmod 640 \
    "$WAZUH_DIR/logs/injection-incidents.log" \
    "$WAZUH_DIR/logs/injection-response.log"

# ------------------------------------------------------------
# Validate Wazuh
# ------------------------------------------------------------

echo
echo "Validating Wazuh configuration..."

"$WAZUH_DIR/bin/wazuh-analysisd" -t

# ------------------------------------------------------------
# Restart Wazuh
# ------------------------------------------------------------

echo
echo "[12/12] Restarting Wazuh..."

systemctl enable wazuh-manager
systemctl restart wazuh-manager

sleep 5

if systemctl is-active --quiet wazuh-manager; then
    echo "Wazuh Manager is running."
else
    echo
    echo "ERROR: Wazuh Manager failed to start."
    systemctl status wazuh-manager --no-pager
    exit 1
fi

# ------------------------------------------------------------
# Final information
# ------------------------------------------------------------

IP_ADDRESS=$(hostname -I | awk '{print $1}')

echo
echo "============================================================"
echo " INSTALLATION COMPLETE"
echo "============================================================"
echo
echo "Juice Shop:"
echo
echo "  http://$IP_ADDRESS:3000"
echo
echo "Wazuh:"
echo
echo "  Manager: RUNNING"
echo
echo "Detection:"
echo
echo "  SQL Injection"
echo "  SQLi Authentication Bypass"
echo "  Cross-Site Scripting (XSS)"
echo "  Command Injection"
echo "  Server-Side Template Injection (SSTI)"
echo
echo "Active Response:"
echo
echo "  High-confidence injection alerts"
echo "  60 second IP block"
echo
echo "Logs:"
echo
echo "  /var/ossec/logs/injection-incidents.log"
echo "  /var/ossec/logs/injection-response.log"
echo "  /home/juice/juice-shop/logs/security.log"
echo
echo "Useful commands:"
echo
echo "  sudo systemctl status juice-shop"
echo "  sudo systemctl status wazuh-manager"
echo "  sudo tail -f /var/ossec/logs/injection-incidents.log"
echo "  sudo tail -f /var/ossec/logs/injection-response.log"
echo
echo "============================================================"
