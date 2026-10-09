#!/bin/bash

set -e

# ============================================================
# OWASP Juice Shop + Wazuh Injection Detection Installer
# ============================================================

JUICE_SHOP_DIR="/home/juice/juice-shop"
LOGIN_FILE="$JUICE_SHOP_DIR/routes/login.ts"

WAZUH_DIR="/var/ossec"
WAZUH_RULE_DIR="$WAZUH_DIR/etc/rules"
WAZUH_RULE_FILE="$WAZUH_RULE_DIR/injection_rules.xml"

ACTIVE_RESPONSE_DIR="$WAZUH_DIR/active-response/bin"
ACTIVE_RESPONSE_FILE="$ACTIVE_RESPONSE_DIR/injection-block.py"

SECURITY_LOG_DIR="$JUICE_SHOP_DIR/logs"
SECURITY_LOG="$SECURITY_LOG_DIR/security.log"

INCIDENT_LOG="$WAZUH_DIR/logs/injection-incidents.log"
RESPONSE_LOG="$WAZUH_DIR/logs/injection-response.log"

WAZUH_REPO_FILE="/etc/apt/sources.list.d/wazuh.list"
WAZUH_KEY="/usr/share/keyrings/wazuh.gpg"

echo "============================================================"
echo " OWASP Juice Shop + Wazuh Injection Detection Installer"
echo "============================================================"
echo

# ============================================================
# Root check
# ============================================================

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run this script with sudo."
    echo
    echo "Example:"
    echo "  sudo ./install.sh"
    exit 1
fi

# ============================================================
# Detect Juice Shop user
# ============================================================

if id juice >/dev/null 2>&1; then
    JUICE_USER="juice"
else
    JUICE_USER="$(stat -c '%U' "$JUICE_SHOP_DIR" 2>/dev/null || echo "juice")"
fi

echo "Juice Shop user: $JUICE_USER"
echo "Juice Shop path: $JUICE_SHOP_DIR"
echo

# ============================================================
# 1. Check operating system
# ============================================================

echo "[1/10] Checking operating system..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Operating system: $PRETTY_NAME"
else
    echo "WARNING: Unable to determine operating system."
fi

echo

# ============================================================
# 2. Install required dependencies
# ============================================================

echo "[2/10] Installing dependencies..."

export DEBIAN_FRONTEND=noninteractive

apt-get update || true

apt-get install -y \
    curl \
    wget \
    python3 \
    ca-certificates \
    gnupg \
    lsb-release \
    apt-transport-https \
    iptables

echo

# ============================================================
# 3. Check Node.js and npm
# ============================================================

echo "[3/10] Checking Node.js and npm..."

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: Node.js is not installed."
    echo
    echo "The provided Juice Shop VM should already contain Node.js."
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "ERROR: npm is not installed."
    exit 1
fi

echo "Node.js: $(node --version)"
echo "npm:     $(npm --version)"
echo

# ============================================================
# 4. Check provided Juice Shop installation
# ============================================================

echo "[4/10] Checking the provided Juice Shop installation..."

if [ ! -d "$JUICE_SHOP_DIR" ]; then
    echo "ERROR: Juice Shop was not found at:"
    echo "  $JUICE_SHOP_DIR"
    echo
    echo "This installer expects the provided Juice Shop VM."
    echo "It will NOT clone or reinstall Juice Shop."
    exit 1
fi

if [ ! -f "$JUICE_SHOP_DIR/package.json" ]; then
    echo "ERROR: package.json was not found."
    echo "The directory does not appear to be a Juice Shop installation."
    exit 1
fi

if [ ! -f "$LOGIN_FILE" ]; then
    echo "ERROR: routes/login.ts was not found:"
    echo "  $LOGIN_FILE"
    exit 1
fi

echo "Juice Shop found at:"
echo "  $JUICE_SHOP_DIR"
echo

# ============================================================
# 5. Check / install Wazuh Manager
# ============================================================

echo "[5/10] Checking Wazuh installation..."

# ------------------------------------------------------------
# Check if Wazuh Manager is already installed
# ------------------------------------------------------------

if [ -d "$WAZUH_DIR" ] && command -v /var/ossec/bin/wazuh-analysisd >/dev/null 2>&1; then

    echo "Wazuh Manager is already installed."
    echo "Installation path:"
    echo "  $WAZUH_DIR"

else

    echo "Wazuh Manager was not found."
    echo "Installing Wazuh Manager..."
    echo

    # --------------------------------------------------------
    # Install Wazuh GPG key
    # --------------------------------------------------------

    echo "Installing Wazuh repository GPG key..."

    mkdir -p /usr/share/keyrings

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring \
        --keyring "$WAZUH_KEY" \
        --import

    chmod 644 "$WAZUH_KEY"

    # --------------------------------------------------------
    # Configure Wazuh repository
    # --------------------------------------------------------

    echo "Configuring Wazuh repository..."

    cat > "$WAZUH_REPO_FILE" <<EOF
deb [signed-by=$WAZUH_KEY] https://packages.wazuh.com/4.x/apt/ stable main
EOF

    # --------------------------------------------------------
    # Update package information
    # --------------------------------------------------------

    echo "Updating package information..."

    apt-get update

    # --------------------------------------------------------
    # Install Wazuh Manager
    # --------------------------------------------------------

    echo "Installing Wazuh Manager..."

    apt-get install -y wazuh-manager

    # --------------------------------------------------------
    # Enable Wazuh Manager
    # --------------------------------------------------------

    systemctl daemon-reload
    systemctl enable wazuh-manager

    echo
    echo "Wazuh Manager installation completed."

fi

# ------------------------------------------------------------
# Verify Wazuh installation
# ------------------------------------------------------------

if [ ! -d "$WAZUH_DIR" ]; then
    echo "ERROR: Wazuh installation failed."
    echo "Expected:"
    echo "  $WAZUH_DIR"
    exit 1
fi

if [ ! -f "$WAZUH_DIR/etc/ossec.conf" ]; then
    echo "ERROR: Wazuh configuration was not found."
    exit 1
fi

if [ ! -x "$WAZUH_DIR/bin/wazuh-analysisd" ]; then
    echo "ERROR: Wazuh analysis engine was not found."
    exit 1
fi

echo "Wazuh Manager is available."
echo

# ============================================================
# 6. Create Juice Shop logging
# ============================================================

echo "[6/10] Creating Juice Shop logging..."

mkdir -p "$SECURITY_LOG_DIR"

touch "$SECURITY_LOG"

chown "$JUICE_USER":"$JUICE_USER" "$SECURITY_LOG"
chmod 640 "$SECURITY_LOG"

echo "Security log:"
echo "  $SECURITY_LOG"
echo

# ============================================================
# 7. Install Juice Shop security telemetry
# ============================================================

echo "[7/10] Installing Juice Shop security telemetry..."

# ------------------------------------------------------------
# Backup login.ts
# ------------------------------------------------------------

if [ ! -f "${LOGIN_FILE}.before-injection" ]; then
    cp "$LOGIN_FILE" "${LOGIN_FILE}.before-injection"
    echo "Created backup:"
    echo "  ${LOGIN_FILE}.before-injection"
else
    echo "Existing backup found."
fi

# ------------------------------------------------------------
# Patch login.ts
# ------------------------------------------------------------

python3 - "$LOGIN_FILE" "$SECURITY_LOG" <<'PY'
import sys

path = sys.argv[1]
security_log = sys.argv[2]

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# ------------------------------------------------------------
# Add fs import
# ------------------------------------------------------------

if "import fs from 'fs'" not in content:

    express_import = (
        "import { type Request, type Response, type NextFunction } "
        "from 'express'"
    )

    if express_import not in content:
        print("ERROR: Could not find Express import.")
        sys.exit(1)

    content = content.replace(
        express_import,
        express_import + "\nimport fs from 'fs'",
        1
    )

# ------------------------------------------------------------
# Add telemetry function
# ------------------------------------------------------------

if "function logLoginEvent" not in content:

    marker = "export function login () {"

    if marker not in content:
        print("ERROR: Could not find:")
        print("  export function login () {")
        sys.exit(1)

    telemetry = f"""
function logLoginEvent (req: Request, status: number) {{
  const event = {{
    event: 'login',
    srcip: req.ip,
    method: req.method,
    path: req.path,
    email: req.body?.email || '',
    status
  }}

  try {{
    fs.appendFileSync(
      '{security_log}',
      JSON.stringify(event) + '\\n'
    )
  }} catch (error) {{
    console.error('Failed to write security telemetry:', error)
  }}
}}

"""

    content = content.replace(
        marker,
        telemetry + marker,
        1
    )

# ------------------------------------------------------------
# TOTP response
# ------------------------------------------------------------

old = """if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({"""

new = """if (user.data?.id && user.data.totpSecret !== '') {
          logLoginEvent(req, 401)
          res.status(401).json({"""

if old in content and "logLoginEvent(req, 401)" not in content:
    content = content.replace(old, new, 1)

# ------------------------------------------------------------
# Successful authentication
# ------------------------------------------------------------

old = """} else if (user.data?.id) {
          // @ts-expect-error FIXME some properties missing in user - vuln-code-snippet hide-line
          afterLogin(user, res, next)"""

new = """} else if (user.data?.id) {
          logLoginEvent(req, 200)
          // @ts-expect-error FIXME some properties missing in user - vuln-code-snippet hide-line
          afterLogin(user, res, next)"""

if old in content and "logLoginEvent(req, 200)" not in content:
    content = content.replace(old, new, 1)

# ------------------------------------------------------------
# Invalid credentials
# ------------------------------------------------------------

old = """} else {
          res.status(401).send(res.__('Invalid email or password.'))
        }"""

new = """} else {
          logLoginEvent(req, 401)
          res.status(401).send(res.__('Invalid email or password.'))
        }"""

if old in content and new not in content:
    content = content.replace(old, new, 1)

# ------------------------------------------------------------
# Database / login error
# ------------------------------------------------------------

old = """}).catch((error: Error) => {
        next(error)
      })
  }

  // vuln-code-snippet end loginAdminChallenge"""

new = """}).catch((error: Error) => {
        logLoginEvent(req, 500)
        next(error)
      })
  }

  // vuln-code-snippet end loginAdminChallenge"""

if old in content and "logLoginEvent(req, 500)" not in content:
    content = content.replace(old, new, 1)

# ------------------------------------------------------------
# Write file
# ------------------------------------------------------------

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Juice Shop login telemetry installed successfully.")
PY

# ------------------------------------------------------------
# Verify telemetry
# ------------------------------------------------------------

if ! grep -q "function logLoginEvent" "$LOGIN_FILE"; then
    echo "ERROR: logLoginEvent was not installed."
    exit 1
fi

echo "Security telemetry configured."
echo

# ============================================================
# 8. Build Juice Shop server
# ============================================================

echo "[8/10] Building Juice Shop server..."

cd "$JUICE_SHOP_DIR"

runuser -u "$JUICE_USER" -- npm run build:server

echo "Juice Shop server build completed."
echo

# ============================================================
# 9. Install Wazuh injection detection
# ============================================================

echo "[9/10] Installing Wazuh injection detection..."

mkdir -p "$WAZUH_RULE_DIR"
mkdir -p "$ACTIVE_RESPONSE_DIR"

# ------------------------------------------------------------
# Injection detection rules
# ------------------------------------------------------------

cat > "$WAZUH_RULE_FILE" <<'EOF'
<group name="web,injection,">

  <!-- =======================================================
       SQL INJECTION
       ======================================================= -->

  <rule id="100100" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)(%27|'|%22|").*(union|select|or|and|drop|insert|update|delete|sleep|benchmark)</url>
    <description>Possible SQL injection pattern detected in HTTP request</description>
    <group>web,injection,sqli,</group>
  </rule>

  <rule id="100102" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)union(\+|%20|\s)+(all(\+|%20|\s)+)?select</url>
    <description>SQL injection UNION SELECT pattern detected</description>
    <group>web,injection,sqli,</group>
  </rule>

  <rule id="100103" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)(%27|'|%22|").*(select|insert|update|delete|drop)</url>
    <description>SQL injection database manipulation pattern detected</description>
    <group>web,injection,sqli,</group>
  </rule>

  <rule id="100104" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)(sleep|benchmark)(%28|\()</url>
    <description>Possible time-based SQL injection detected</description>
    <group>web,injection,sqli,time_based,</group>
  </rule>

  <rule id="100105" level="9">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)(%27|%22).*(--|%2d%2d|%23)</url>
    <description>SQL injection quote and comment pattern detected</description>
    <group>web,injection,sqli,</group>
  </rule>

  <rule id="100101" level="12">
    <if_group>sqli</if_group>
    <id type="pcre2">^(400|500)$</id>
    <description>SQL injection pattern followed by HTTP client/server error</description>
    <group>web,injection,sqli,high_severity,</group>
  </rule>

  <rule id="100106" level="12">
    <decoded_as>json</decoded_as>
    <field name="event">^login$</field>
    <field name="path">^/rest/user/login$</field>
    <field name="email" type="pcre2">(?i)(%27|'|%22|").*(\bor\b|\band\b).*(=|--|%2d%2d|#|%23)</field>
    <description>SQL injection authentication bypass attempt detected in login request</description>
    <group>web,injection,sqli,high_severity,</group>
  </rule>

  <!-- =======================================================
       XSS
       ======================================================= -->

  <rule id="100110" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%3c.*(script|iframe|img|svg|onerror|onload|javascript)</url>
    <description>Possible XSS payload detected in HTTP request</description>
    <group>web,injection,xss,</group>
  </rule>

  <rule id="100112" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%3c(%2f)?script</url>
    <description>XSS script element detected in HTTP request</description>
    <group>web,injection,xss,</group>
  </rule>

  <rule id="100113" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%3ciframe</url>
    <description>XSS iframe element detected in HTTP request</description>
    <group>web,injection,xss,</group>
  </rule>

  <rule id="100114" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%3c(img|svg)(%20|\+|%3e)</url>
    <description>XSS executable HTML element detected in HTTP request</description>
    <group>web,injection,xss,</group>
  </rule>

  <rule id="100115" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)javascript(%3a|:)</url>
    <description>XSS JavaScript URI detected in HTTP request</description>
    <group>web,injection,xss,</group>
  </rule>

  <rule id="100116" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)(onerror|onload|onclick|onmouseover|onfocus)(%3d|=)</url>
    <description>XSS JavaScript event handler detected in HTTP request</description>
    <group>web,injection,xss,</group>
  </rule>

  <rule id="100111" level="12">
    <if_group>xss</if_group>
    <id type="pcre2">^(400|500)$</id>
    <description>XSS payload followed by HTTP client/server error</description>
    <group>web,injection,xss,high_severity,</group>
  </rule>

  <!-- =======================================================
       COMMAND INJECTION
       ======================================================= -->

  <rule id="100120" level="10">
    <if_sid>31100,31108</if_sid>
    <url type="pcre2">(?i)(%3b|;)(whoami|id|uname|cat|ls|pwd|curl|wget|bash|sh)(%20|\+|%2f|/|$)</url>
    <description>Possible command injection payload detected in HTTP request</description>
    <group>web,injection,command_injection,</group>
  </rule>

  <rule id="100122" level="10">
    <if_sid>31100,31108</if_sid>
    <url type="pcre2">(?i)(%7c|%7c%7c|\|)(whoami|id|uname|cat|ls|pwd|curl|wget|bash|sh)(%20|\+|%2f|/|$)</url>
    <description>Command injection pipe or logical OR pattern detected</description>
    <group>web,injection,command_injection,</group>
  </rule>

  <rule id="100123" level="10">
    <if_sid>31100,31108</if_sid>
    <url type="pcre2">(?i)(%26%26|&amp;&amp;)(whoami|id|uname|cat|ls|pwd|curl|wget|bash|sh)(%20|\+|%2f|/|$)</url>
    <description>Command injection logical AND pattern detected</description>
    <group>web,injection,command_injection,</group>
  </rule>

  <rule id="100125" level="9">
    <if_sid>31100,31108</if_sid>
    <url type="pcre2">(?i)(%3b|%7c|%26%26|%7c%7c).*(bash|sh|cmd|powershell)</url>
    <description>Possible shell execution pattern detected in HTTP request</description>
    <group>web,injection,command_injection,</group>
  </rule>

  <rule id="100124" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%7c%7c(whoami|id|uname|cat|ls|pwd|curl|wget|bash|sh)(%20|\+|%2f|/|$)</url>
    <description>Command injection logical OR pattern detected</description>
    <group>web,injection,command_injection,</group>
  </rule>

  <rule id="100121" level="12">
    <if_group>command_injection</if_group>
    <id type="pcre2">^(400|500)$</id>
    <description>Command injection pattern followed by HTTP client/server error</description>
    <group>web,injection,command_injection,high_severity,</group>
  </rule>

  <!-- =======================================================
       SSTI
       ======================================================= -->

  <rule id="100130" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%7b%7b.*%7d%7d</url>
    <description>Possible SSTI double-curly template expression detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100132" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%7b%25.*%25%7d</url>
    <description>SSTI template statement syntax detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100133" level="9">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%24%7b.*%7d</url>
    <description>SSTI dollar-brace expression detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100134" level="9">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%23%7b.*%7d</url>
    <description>SSTI hash-brace expression detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100135" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%3c%25.*%25%3e</url>
    <description>SSTI server-side template delimiter detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100136" level="10">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)(constructor|process|global|require|config).*(%28|\(|%5b|\[|%2e|\.)</url>
    <description>Suspicious SSTI runtime object access detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100137" level="9">
    <if_sid>31100</if_sid>
    <url type="pcre2">(?i)%7b%7b[0-9]+(%2a|\*)[0-9]+%7d%7d</url>
    <description>Possible SSTI arithmetic evaluation probe detected</description>
    <group>web,injection,ssti,</group>
  </rule>

  <rule id="100131" level="12">
    <if_group>ssti</if_group>
    <id type="pcre2">^(400|500)$</id>
    <description>SSTI pattern followed by HTTP client/server error</description>
    <group>web,injection,ssti,high_severity,</group>
  </rule>

</group>
EOF

chown root:wazuh "$WAZUH_RULE_FILE"
chmod 640 "$WAZUH_RULE_FILE"

echo "Wazuh injection rules installed."

# ============================================================
# Active Response
# ============================================================

cat > "$ACTIVE_RESPONSE_FILE" <<'PY'
#!/usr/bin/python3

import sys
import json
import subprocess
from datetime import datetime

RESPONSE_LOG = "/var/ossec/logs/injection-response.log"
INCIDENT_LOG = "/var/ossec/logs/injection-incidents.log"


def log_response(message):
    with open(RESPONSE_LOG, "a") as f:
        f.write(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + " "
            + message
            + "\n"
        )


def log_incident(incident):
    with open(INCIDENT_LOG, "a") as f:
        f.write(json.dumps(incident) + "\n")


def normalize_ip(ip):
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


def get_attack_type(rule_id):
    attack_types = {
        "100101": "SQLI",
        "100106": "SQLI_AUTH_BYPASS",
        "100111": "XSS",
        "100121": "COMMAND_INJECTION",
        "100131": "SSTI"
    }

    return attack_types.get(str(rule_id), "INJECTION")


def iptables_rule_exists(ip):
    result = subprocess.run(
        [
            "/usr/sbin/iptables",
            "-C",
            "INPUT",
            "-s",
            ip,
            "-j",
            "DROP"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def block_ip(ip):
    if not iptables_rule_exists(ip):
        subprocess.run(
            [
                "/usr/sbin/iptables",
                "-I",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ],
            check=False
        )


def unblock_ip(ip):
    if iptables_rule_exists(ip):
        subprocess.run(
            [
                "/usr/sbin/iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ],
            check=False
        )


def main():

    line = sys.stdin.readline()

    if not line:
        log_response("ERROR no input received")
        return 1

    try:
        data = json.loads(line)
    except Exception as e:
        log_response("ERROR invalid JSON: " + str(e))
        return 1

    command = data.get("command", "")

    alert = data.get(
        "parameters",
        {}
    ).get(
        "alert",
        {}
    )

    alert_data = alert.get("data", {})

    srcip = alert_data.get("srcip", "")

    ip = normalize_ip(srcip)

    rule_id = str(
        alert.get(
            "rule",
            {}
        ).get(
            "id",
            ""
        )
    )

    rule_description = (
        alert.get(
            "rule",
            {}
        ).get(
            "description",
            ""
        )
    )

    attack_type = get_attack_type(rule_id)

    timestamp = datetime.now().strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    log_response(
        "RECEIVED command={} rule={} attack={} original_ip={} normalized_ip={}".format(
            command,
            rule_id,
            attack_type,
            srcip,
            ip
        )
    )

    if not ip:
        log_response("ERROR source IP missing")
        return 1

    if ip == "127.0.0.1":
        log_response("SKIPPED localhost")

        incident = {
            "timestamp": timestamp,
            "incident": attack_type,
            "severity": "HIGH",
            "rule_id": rule_id,
            "source_ip": ip,
            "action": "SKIPPED_LOCALHOST",
            "description": rule_description
        }

        log_incident(incident)

        return 0

    if command == "add":

        check_message = {
            "version": 1,
            "origin": {
                "name": "injection-block",
                "module": "active-response"
            },
            "command": "check_keys",
            "parameters": {
                "keys": [ip]
            }
        }

        print(
            json.dumps(check_message),
            flush=True
        )

        response_line = sys.stdin.readline()

        if not response_line:
            log_response(
                "ERROR no check_keys response"
            )
            return 1

        try:
            response = json.loads(response_line)
        except Exception as e:
            log_response(
                "ERROR invalid check_keys response: " + str(e)
            )
            return 1

        response_command = response.get(
            "command",
            ""
        )

        log_response(
            "CHECK_KEYS result={}".format(
                response_command
            )
        )

        if response_command == "abort":
            log_response(
                "ABORTED ip={}".format(ip)
            )
            return 0

        if response_command != "continue":
            log_response(
                "ERROR unexpected check_keys response={}".format(
                    response_command
                )
            )
            return 1

        incident = {
            "timestamp": timestamp,
            "incident": attack_type,
            "severity": "HIGH",
            "rule_id": rule_id,
            "source_ip": ip,
            "action": "BLOCKED",
            "duration_seconds": 60,
            "description": rule_description
        }

        log_incident(incident)

        block_ip(ip)

        log_response(
            "BLOCKED ip={} rule={} attack={}".format(
                ip,
                rule_id,
                attack_type
            )
        )

    elif command == "delete":

        unblock_ip(ip)

        log_response(
            "UNBLOCKED ip={} rule={} attack={}".format(
                ip,
                rule_id,
                attack_type
            )
        )

        incident = {
            "timestamp": timestamp,
            "incident": attack_type,
            "severity": "HIGH",
            "rule_id": rule_id,
            "source_ip": ip,
            "action": "UNBLOCKED",
            "description": rule_description
        }

        log_incident(incident)

    else:

        log_response(
            "ERROR unknown command={}".format(
                command
            )
        )

        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
PY

chmod 750 "$ACTIVE_RESPONSE_FILE"
chown root:wazuh "$ACTIVE_RESPONSE_FILE"

# ------------------------------------------------------------
# Active Response logs
# ------------------------------------------------------------

touch "$INCIDENT_LOG"
touch "$RESPONSE_LOG"

chown wazuh:wazuh "$INCIDENT_LOG"
chown wazuh:wazuh "$RESPONSE_LOG"

chmod 640 "$INCIDENT_LOG"
chmod 640 "$RESPONSE_LOG"

echo "Active Response installed."
echo

# ============================================================
# 10. Configure Wazuh
# ============================================================

echo "[10/10] Configuring Wazuh..."

OSSEC_CONFIG="$WAZUH_DIR/etc/ossec.conf"

# ------------------------------------------------------------
# Backup configuration
# ------------------------------------------------------------

if [ ! -f "${OSSEC_CONFIG}.before-injection" ]; then
    cp "$OSSEC_CONFIG" "${OSSEC_CONFIG}.before-injection"
fi

# ------------------------------------------------------------
# Add security JSON log
# ------------------------------------------------------------

if ! grep -qF "$SECURITY_LOG" "$OSSEC_CONFIG"; then

    python3 - "$OSSEC_CONFIG" "$SECURITY_LOG" <<'PY'
import sys

path = sys.argv[1]
security_log = sys.argv[2]

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

block = f"""
<!-- Juice Shop injection security telemetry -->
<localfile>
  <location>{security_log}</location>
  <log_format>json</log_format>
</localfile>
"""

if "</ossec_config>" not in content:
    print("ERROR: Could not find </ossec_config>")
    sys.exit(1)

content = content.replace(
    "</ossec_config>",
    block + "\n</ossec_config>",
    1
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
PY

    echo "Security log added to Wazuh."

else
    echo "Security log already configured."
fi

# ------------------------------------------------------------
# Add access log
# ------------------------------------------------------------

ACCESS_LOG="$SECURITY_LOG_DIR/access.log.%Y-%m-%d"

if ! grep -qF "$ACCESS_LOG" "$OSSEC_CONFIG"; then

    python3 - "$OSSEC_CONFIG" "$ACCESS_LOG" <<'PY'
import sys

path = sys.argv[1]
access_log = sys.argv[2]

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

block = f"""
<!-- Juice Shop HTTP access log -->
<localfile>
  <location>{access_log}</location>
  <log_format>apache</log_format>
</localfile>
"""

if "</ossec_config>" not in content:
    print("ERROR: Could not find </ossec_config>")
    sys.exit(1)

content = content.replace(
    "</ossec_config>",
    block + "\n</ossec_config>",
    1
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
PY

    echo "Access log added to Wazuh."

else
    echo "Access log already configured."
fi

# ------------------------------------------------------------
# Add Active Response
# ------------------------------------------------------------

if ! grep -q "<name>injection-block</name>" "$OSSEC_CONFIG"; then

    python3 - "$OSSEC_CONFIG" <<'PY'
import sys

path = sys.argv[1]

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

block = """
<!-- Injection Detection Active Response -->

<command>
  <name>injection-block</name>
  <executable>injection-block.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>injection-block</command>
  <location>server</location>
  <rules_id>100101,100106,100111,100121,100131</rules_id>
  <timeout>60</timeout>
</active-response>
"""

if "</ossec_config>" not in content:
    print("ERROR: Could not find </ossec_config>")
    sys.exit(1)

content = content.replace(
    "</ossec_config>",
    block + "\n</ossec_config>",
    1
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
PY

    echo "Active Response added."

else
    echo "Active Response already configured."
fi

# ============================================================
# Validate Wazuh
# ============================================================

echo
echo "Validating Wazuh configuration..."

if "$WAZUH_DIR/bin/wazuh-analysisd" -t; then
    echo "Wazuh configuration validation: OK"
else
    echo
    echo "ERROR: Wazuh configuration validation failed."
    echo
    echo "Backup:"
    echo "  ${OSSEC_CONFIG}.before-injection"
    exit 1
fi

# ============================================================
# Start / restart Wazuh
# ============================================================

echo
echo "Starting Wazuh Manager..."

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl restart wazuh-manager

sleep 5

if systemctl is-active --quiet wazuh-manager; then
    echo "Wazuh Manager is running."
else
    echo "ERROR: Wazuh Manager failed to start."
    systemctl status wazuh-manager --no-pager
    exit 1
fi

# ============================================================
# Restart Juice Shop
# ============================================================

echo
echo "Restarting Juice Shop..."

if systemctl list-unit-files | grep -q "^juice-shop.service"; then

    systemctl restart juice-shop

    sleep 3

    if systemctl is-active --quiet juice-shop; then
        echo "Juice Shop service is running."
    else
        echo "WARNING: Juice Shop service is not running."
        systemctl status juice-shop --no-pager
    fi

else

    echo "No juice-shop.service found."
    echo
    echo "Juice Shop was rebuilt successfully."
    echo "Start it manually with:"
    echo
    echo "  cd $JUICE_SHOP_DIR"
    echo "  npm start"
fi

# ============================================================
# Final verification
# ============================================================

echo
echo "============================================================"
echo " Installation completed successfully"
echo "============================================================"
echo

echo "Juice Shop:"
echo "  $JUICE_SHOP_DIR"

echo
echo "Security telemetry:"
echo "  $SECURITY_LOG"

echo
echo "Wazuh rules:"
echo "  $WAZUH_RULE_FILE"

echo
echo "Active Response:"
echo "  $ACTIVE_RESPONSE_FILE"

echo
echo "Incident log:"
echo "  $INCIDENT_LOG"

echo
echo "Response log:"
echo "  $RESPONSE_LOG"

echo
echo "Wazuh status:"
systemctl is-active wazuh-manager || true

echo
echo "Useful commands:"
echo
echo "  sudo tail -f $SECURITY_LOG"
echo
echo "  sudo tail -f $INCIDENT_LOG"
echo
echo "  sudo tail -f $RESPONSE_LOG"
echo
echo "  sudo iptables -L INPUT -n --line-numbers"
echo
echo "  sudo systemctl status wazuh-manager"
echo

echo "============================================================"
echo " Injection detection is ready."
echo "============================================================"
