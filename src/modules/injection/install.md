# Installation Instructions

## Juice Shop Injection Detection and Response

This project adds Wazuh-based detection and automated response to the
**provided Ubuntu Juice Shop VM**.

The provided VM already has OWASP Juice Shop installed using `npm`.
This installer therefore **does not install or clone Juice Shop**.

Instead, it configures the existing Juice Shop installation and installs
the Wazuh components required for injection detection and response.

## Requirements

Use the provided Ubuntu Juice Shop VM.

The VM should have:

- Ubuntu Linux
- OWASP Juice Shop already installed using `npm`
- Internet access
- `sudo` access
- An isolated lab network

The installer expects the existing Juice Shop installation at:

```text
/home/juice/juice-shop
```
## Expamd VM Disk

Expand the juice VM to 40GB:

1.Expand Vm in vm setting
2.In ubuntu


**Warning:** OWASP Juice Shop is intentionally vulnerable. Do not expose the Juice Shop service to the public internet.

## 1. Clone the Repository

Clone the team repository:

```bash
git clone https://github.com/ICT30016-EDR1/ICT30016-EDR1.git
```

Enter the repository:

```bash
cd ICT30016-EDR1/src/modules/injection
```

## 2. Make the Installer Executable

```bash
chmod +x install.sh
```

## 3. Run the Installer

```bash
sudo ./install.sh
```

The installer will automatically:

1. Check the existing Juice Shop installation.
2. Install required system dependencies.
3. Configure Juice Shop security telemetry.
4. Compile Juice Shop.
5. Configure the Juice Shop service.
6. Install Wazuh Manager.
7. Install custom injection detection rules.
8. Install Wazuh Active Response.
9. Configure Juice Shop log monitoring.
10. Configure automatic IP blocking.
11. Create incident and response logs.
12. Validate the Wazuh configuration.
13. Restart Wazuh and Juice Shop.

## 4. Verify Juice Shop

Find the VM IP address:

```bash
hostname -I
```

Juice Shop should be available at:

```text
http://<VM-IP>:3000
```

For example:

```text
http://192.168.6.2:3000
```

Check the service:

```bash
sudo systemctl status juice-shop
```

The service should show:

```text
active (running)
```

## 5. Verify Wazuh

Check the Wazuh Manager:

```bash
sudo systemctl status wazuh-manager
```

The service should show:

```text
active (running)
```

Validate the Wazuh configuration:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

## 6. Monitor Detection Events

### Injection Incidents

```bash
sudo tail -f /var/ossec/logs/injection-incidents.log
```

### Active Response

```bash
sudo tail -f /var/ossec/logs/injection-response.log
```

### Juice Shop Security Telemetry

```bash
sudo tail -f /home/juice/juice-shop/logs/security.log
```

### Juice Shop Access Logs

```bash
sudo tail -f /home/juice/juice-shop/logs/access.log.$(date +%Y-%m-%d)
```

## 7. Active Response

The following high-confidence Wazuh rules trigger automatic IP blocking:

| Rule | Detection | Response |
|---|---|---|
| `100101` | SQL Injection | Block source IP |
| `100106` | SQLi Authentication Bypass | Block source IP |
| `100111` | XSS | Block source IP |
| `100121` | Command Injection | Block source IP |
| `100131` | SSTI | Block source IP |

The source IP is blocked using `iptables` for **60 seconds**.

After the timeout expires, Wazuh automatically removes the block.

View current blocks with:

```bash
sudo iptables -L INPUT -n --line-numbers
```

## 8. Useful Commands

Restart Juice Shop:

```bash
sudo systemctl restart juice-shop
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

View recent injection incidents:

```bash
sudo tail -n 20 /var/ossec/logs/injection-incidents.log
```

View recent Active Response events:

```bash
sudo tail -n 20 /var/ossec/logs/injection-response.log
```

Check Juice Shop service logs:

```bash
sudo journalctl -u juice-shop -n 50 --no-pager
```

Check Wazuh service logs:

```bash
sudo journalctl -u wazuh-manager -n 50 --no-pager
```

## 9. Testing

Testing should be performed from a separate Kali Linux VM or another machine on the isolated lab network.

The expected workflow is:

```text
Kali Linux
    |
    | HTTP request
    v
OWASP Juice Shop
    |
    | Access/security logs
    v
Wazuh Manager
    |
    | Custom detection rules
    v
Injection Alert
    |
    | High-confidence rule
    v
Active Response
    |
    v
Source IP blocked for 60 seconds
```

## 10. Troubleshooting

If Juice Shop is not running:

```bash
sudo systemctl status juice-shop
```

Then view its logs:

```bash
sudo journalctl -u juice-shop -n 100 --no-pager
```

If Wazuh is not running:

```bash
sudo systemctl status wazuh-manager
```

Validate the Wazuh configuration:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Then view the Wazuh logs:

```bash
sudo journalctl -u wazuh-manager -n 100 --no-pager
```

## 11. Security Notes

This environment is intended for **educational and controlled security testing only**.

OWASP Juice Shop is intentionally vulnerable. Keep the VM on an isolated lab network and do not expose port `3000` or other vulnerable services directly to the public internet.
