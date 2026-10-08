#!/bin/bash

set -e

# ============================================================
# Juice Shop Injection Detection
# Installation/configuration script
#
# IMPORTANT:
# This script is designed for the provided Ubuntu Juice Shop VM.
# OWASP Juice Shop is already installed using npm.
#
# This script does NOT clone or reinstall Juice Shop.
#
# Installs/configures:
#   - Required dependencies
#   - Wazuh Manager (if not already installed)
#   - Juice Shop security telemetry
#   - Juice Shop systemd service (only if required)
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
echo "[1/10] Updating system packages..."

apt-get update
apt-get upgrade -y

# ------------------------------------------------------------
# Install basic dependencies
# ------------------------------------------------------------

echo
echo "[2/10] Installing dependencies..."

apt-get install -y \
    curl \
    wget \
    python3 \
    ca-certificates \
    gnupg \
    lsb-release \
    iptables

# ------------------------------------------------------------
# Check Node.js / npm
# ------------------------------------------------------------

echo
echo "[3/10] Checking Node.js and npm..."

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: Node.js is not installed."
    echo "The provided Juice Shop VM is expected to already contain Node.js."
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "ERROR: npm is not installed."
    exit 1
fi

echo "Node.js: $(node --version)"
echo "npm:     $(npm --version)"

# ------------------------------------------------------------

# ------------------------------------------------------------

echo
echo "[4/10] Checking the provided Juice Shop installation..."

if ! id "$JUICE_USER" >/dev/null 2>&1; then
    echo "ERROR: User '$JUICE_USER' does not exist."
    echo "This installer expects the provided Juice Shop VM."
    exit 1
fi

if [ ! -d "$JUICE_DIR" ]; then
    echo "ERROR: Juice Shop directory was not found:"
    echo "  $JUICE_DIR"
    echo
    echo "This installer does not install or clone Juice Shop."
    exit 1
fi

if [ ! -f "$JUICE_DIR/package.json" ]; then
    echo "ERROR: $JUICE_DIR/package.json was not found."
    exit 1
fi

if [ ! -f "$JUICE_DIR/routes/login.ts" ]; then
    echo "ERROR: $JUICE_DIR/routes/login.ts was not found."
    exit 1
fi

echo "Juice Shop found at $JUICE_DIR"

# ------------------------------------------------------------
# Create Juice Shop logs
# ------------------------------------------------------------

# ------------------------------------------------------------

echo
echo "[6/10] Creating Juice Shop logging..."

mkdir -p "$JUICE_DIR/logs"

touch "$JUICE_DIR/logs/security.log"

chown -R "$JUICE_USER:$JUICE_USER" "$JUICE_DIR/logs"

chmod 750 "$JUICE_DIR/logs"
chmod 640 "$JUICE_DIR/logs/security.log"

# ------------------------------------------------------------
# Install login telemetry
# ------------------------------------------------------------

echo
echo "[7/10] Installing Juice Shop security telemetry..."

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

runuser -u "$JUICE_USER" -- npm run build:server

# ------------------------------------------------------------
# Configure Juice Shop systemd service
# ------------------------------------------------------------

echo
echo "[6/10] Checking Juice Shop systemd service..."

SERVICE_FILE="/etc/systemd/system/juice-shop.service"

if systemctl list-unit-files --type=service | grep -q '^juice-shop.service'; then
    echo "Existing juice-shop.service found."
    echo "The existing service will be preserved."
else
    echo "No Juice Shop service found. Creating one..."

    cat > "$SERVICE_FILE" <<'EOF'
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
fi

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

# ------------------------------------------------------------

echo
echo "[7/10] Installing Wazuh Manager..."

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
# Install Wazuh injection rules safely
# ------------------------------------------------------------

echo
echo "[8/10] Installing Wazuh injection detection..."

mkdir -p "$WAZUH_DIR/etc/rules"
mkdir -p "$AR_DIR"

RULE_SOURCE="$SCRIPT_DIR/wazuh/injection_rules.xml"
RULE_DEST="$WAZUH_DIR/etc/rules/injection_rules.xml"

if [ ! -f "$RULE_SOURCE" ]; then
    echo "ERROR: Project Wazuh rules were not found:"
    echo "  $RULE_SOURCE"
    echo
    echo "The repository should contain wazuh/injection_rules.xml."
    exit 1
fi

# Use a separate rule file instead of replacing local_rules.xml.
# This preserves existing custom Wazuh rules on the provided VM.
cp "$RULE_SOURCE" "$RULE_DEST"

chown root:wazuh "$RULE_DEST"
chmod 660 "$RULE_DEST"

# ------------------------------------------------------------

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
# Configure Wazuh without overwriting ossec.conf
# ------------------------------------------------------------

echo
echo "[9/10] Configuring Wazuh..."

OSSEC="$WAZUH_DIR/etc/ossec.conf"

if [ ! -f "$OSSEC" ]; then
    echo "ERROR: Wazuh configuration was not found:"
    echo "  $OSSEC"
    exit 1
fi

if [ ! -f "$OSSEC.before-injection-detection" ]; then
    cp "$OSSEC" "$OSSEC.before-injection-detection"
fi

python3 <<'PY'
from pathlib import Path

config = Path("/var/ossec/etc/ossec.conf")
text = config.read_text()

blocks = [
    ("Juice Shop access log", """    <!-- OWASP Juice Shop access log -->
    <localfile>
      <location>/home/juice/juice-shop/logs/access.log.%Y-%m-%d</location>
      <log_format>apache</log_format>
    </localfile>
"""),
    ("Juice Shop security telemetry", """    <!-- OWASP Juice Shop security telemetry -->
    <localfile>
      <location>/home/juice/juice-shop/logs/security.log</location>
      <log_format>json</log_format>
    </localfile>
"""),
    ("Injection Active Response", """    <!-- Injection Active Response -->
    <command>
      <name>injection-block</name>
      <executable>injection-block.py</executable>
      <timeout_allowed>yes</timeout_allowed>
    </command>
"""),
    ("Automatically block high-confidence injection attacks", """    <!-- Automatically block high-confidence injection attacks -->
    <active-response>
      <disabled>no</disabled>
      <command>injection-block</command>
      <location>server</location>
      <rules_id>100101,100106,100111,100121,100131</rules_id>
      <timeout>60</timeout>
    </active-response>
""")
]

for marker, block in blocks:
    if marker not in text:
        if "</ossec_config>" not in text:
            raise SystemExit("ERROR: </ossec_config> not found in ossec.conf")
        text = text.replace(
            "</ossec_config>",
            block.rstrip() + "\n</ossec_config>",
            1
        )

config.write_text(text)
PY


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
echo "[10/10] Restarting Wazuh..."

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
echo " CONFIGURATION COMPLETE"
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
