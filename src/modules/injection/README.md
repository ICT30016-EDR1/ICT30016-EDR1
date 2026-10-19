# Juice Shop Injection Detection and Response

This repository contains the custom Wazuh detection and Active Response
configuration developed for the injection-based security monitoring component.

The system is designed to detect high-confidence injection attacks against
OWASP Juice Shop and automatically block the source IP for 30 seconds.

## Detection Coverage

The system detects:

- SQL Injection
- SQL Injection Authentication Bypass
- Cross-Site Scripting (XSS)
- Command Injection
- Server-Side Template Injection (SSTI)

## Repository Structure

```text
injection-detection/
├── README.md
├── install.md
├── install.sh
├── wazuh/
│   ├── local_rules.xml
│   ├── ossec-injection.conf
│   └── injection-block.py
└── juice-shop/
    └── login.ts
```

## Lab Environment

Testing is performed within an isolated lab environment consisting of:

- Kali Linux - attack/testing machine
- OWASP Juice Shop - target application
- Wazuh Manager - detection and response platform
- Custom Wazuh rules - injection detection
- `injection-block.py` - Active Response script

The source IP used during testing is the IP address of the Kali Linux
testing machine.

## Starting the Environment

Start Wazuh:

```bash
sudo systemctl start wazuh-manager
```

Start Juice Shop:

```bash
sudo systemctl start juice-shop
```

Verify both services:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status juice-shop
```

Juice Shop should be accessible at:

```text
http://<JUICE-SHOP-IP>:3000
```

## Conducting Injection Tests

All injection tests should be performed from the Kali Linux VM against the
isolated Juice Shop instance.

For each test:

1. Start Wazuh and verify that Juice Shop is running.
2. Open Juice Shop from the Kali Linux VM.
3. Navigate to the relevant Juice Shop challenge.
4. Enter the appropriate test input into the vulnerable field.
5. Submit the request.
6. Monitor the Wazuh detection logs.
7. Verify that the expected detection rule is triggered.
8. Verify that the Kali source IP is temporarily blocked.
9. Wait for the 30-second Active Response timeout.
10. Verify that the source IP is automatically unblocked.
11. Record the detection and response evidence.

## SQL Injection

Use the Juice Shop SQL Injection challenge.

Submit a SQL injection test through the vulnerable input field.

Expected detection:

```text
Rule: 100101
Attack: SQLI
Severity: HIGH
```

Monitor the detection:

```bash
sudo tail -f /var/ossec/logs/injection-incidents.log
```

Monitor the Active Response:

```bash
sudo tail -f /var/ossec/logs/injection-response.log
```

The Kali source IP should be blocked for 30 seconds.

## SQL Injection Authentication Bypass

Use the Juice Shop login functionality to conduct the SQL Injection
Authentication Bypass test.

Submit the test through the login input fields.

Expected detection:

```text
Rule: 100106
Attack: SQLI_AUTH_BYPASS
Severity: HIGH
```

The source IP should be blocked for 30 seconds following the
high-confidence detection.

## Cross-Site Scripting (XSS)

Use a Juice Shop XSS challenge and submit a harmless XSS test through the
relevant input field.

Expected detection:

```text
Rule: 100111
Attack: XSS
Severity: HIGH
```

Monitor the resulting event:

```bash
sudo tail -f /var/ossec/logs/injection-incidents.log
```

The source IP should be temporarily blocked for 30 seconds.

## Command Injection

Use the Juice Shop Command Injection challenge.

Submit the test through the vulnerable application input provided by the
challenge.

Expected detection:

```text
Rule: 100121
Attack: COMMAND_INJECTION
Severity: HIGH
```

The Wazuh Active Response should block the source IP for 30 seconds.

## Server-Side Template Injection (SSTI)

Use the Juice Shop SSTI challenge and submit a harmless template expression
through the vulnerable input.

Expected detection:

```text
Rule: 100131
Attack: SSTI
Severity: HIGH
```

The source IP should be blocked for 30 seconds after the high-confidence
detection.

## Monitoring Detection Events

During testing, monitor the injection incident log:

```bash
sudo tail -f /var/ossec/logs/injection-incidents.log
```

Monitor Active Response events:

```bash
sudo tail -f /var/ossec/logs/injection-response.log
```

Monitor Wazuh alerts:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

The custom EDR dashboard can also be used to verify that the detected attack
appears as an Injection event.

## Verifying the IP Block

After triggering a high-confidence injection rule, check the firewall rules:

```bash
sudo iptables -L INPUT -n --line-numbers
```

The Kali source IP should appear as a blocked source.

The current Active Response timeout is:

```text
30 seconds
```

After approximately 30 seconds, Wazuh should automatically remove the
temporary block.

## Testing the 30-Second Timeout

To specifically test the Active Response timeout:

1. Trigger one high-confidence injection detection.
2. Immediately check the firewall rules.
3. Confirm that the Kali source IP is blocked.
4. Record the timestamp of the block.
5. Wait approximately 30 seconds.
6. Check the firewall rules again.
7. Confirm that the temporary block has been removed.
8. Confirm the unblock event in the Active Response log.

Monitor the response log with:

```bash
sudo tail -f /var/ossec/logs/injection-response.log
```

A successful test should show a `BLOCKED` event followed by an
`UNBLOCKED` event approximately 30 seconds later.

> **Note:** If another injection request triggers the same Active Response
> during the test, the block may be triggered again.

## Detection Rules

The following rules are configured for injection detection:

| Rule | Attack |
|---|---|
| `100101` | SQL Injection |
| `100106` | SQL Injection Authentication Bypass |
| `100111` | Cross-Site Scripting |
| `100121` | Command Injection |
| `100131` | Server-Side Template Injection |

These high-confidence rules trigger the `injection-block` Active Response.

## Active Response

The Active Response is configured in Wazuh using:

```text
injection-block.py
```

The response:

1. Receives the Wazuh alert.
2. Identifies the source IP associated with the injection event.
3. Adds a temporary firewall block for the source IP.
4. Maintains the block for 30 seconds.
5. Removes the temporary block when the timeout expires.
6. Records the response in the injection response log.

The Active Response configuration uses:

```xml
<timeout>30</timeout>
```

## Evidence Collection

For each attack, collect evidence showing:

- Attack/test performed
- Source IP
- Timestamp
- Wazuh rule triggered
- Attack classification
- Severity
- Active Response action
- Firewall block
- Automatic unblock after 30 seconds

Useful commands:

```bash
sudo tail -n 20 /var/ossec/logs/injection-incidents.log
```

```bash
sudo tail -n 20 /var/ossec/logs/injection-response.log
```

```bash
sudo tail -n 20 /var/ossec/logs/alerts/alerts.json
```

```bash
sudo iptables -L INPUT -n --line-numbers
```

## Troubleshooting

### Wazuh is not running

Check the Wazuh Manager:

```bash
sudo systemctl status wazuh-manager
```

Restart it with:

```bash
sudo systemctl restart wazuh-manager
```

Validate the Wazuh configuration:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

### Juice Shop is not running

Check the Juice Shop service:

```bash
sudo systemctl status juice-shop
```

Restart it with:

```bash
sudo systemctl restart juice-shop
```

### No injection alert appears

Check the injection incident log:

```bash
sudo tail -f /var/ossec/logs/injection-incidents.log
```

Check the Juice Shop security log:

```bash
sudo tail -f /home/juice/juice-shop/logs/security.log
```

Check the Wazuh Manager log:

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

### The source IP remains blocked

Check the firewall:

```bash
sudo iptables -L INPUT -n --line-numbers
```

Check the Active Response log:

```bash
sudo tail -n 20 /var/ossec/logs/injection-response.log
```

If another injection request triggers the rule while the test is running,
the response may be triggered again.

## Safety

All testing must be performed against the isolated OWASP Juice Shop instance
provided for the project.

Do not conduct these tests against systems, applications, networks, or
accounts without explicit authorisation.

The testing procedures are intended for security validation of the project's
detection and Active Response functionality.
