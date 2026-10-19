# Brute Force Module – Password Spraying

## Detection engine

Monitors login attempts and identifies password spraying by looking for repeated failed logins from one source IP against multiple accounts.

| Code lines | file | line |
| --- | --- | --- |
| `brute_force_threshold = 5` | brute_force_detection.py | 66 |
| `spread_threshold = 3` | brute_force_detection.py | 67 |
| `if event.event_type not in {"ssh_auth_attempt", "web_login_attempt"}:` | brute_force_detection.py | 89 |
| `if len(identities) >= spread_threshold:` | brute_force_detection.py | 150 |
| `emit_alert(...)` | brute_force_detection.py | 177 |

The module detects password spraying when a source IP fails authentication against **multiple accounts**.

The detection uses a **60-second window** and requires attempts against at least **3 different identities**.

---

## Response engine

Blocks the source IP when password spraying is detected.

| Code lines | file | line |
| --- | --- | --- |
| `HIGH_BAN_SECONDS = 30` | brute_force_response.py | 54 |
| `CRITICAL_BAN_SECONDS = 3600` | brute_force_response.py | 55 |
| `ufw deny from {ip}` | brute_force_response.py | 150 |

The response engine uses UFW to temporarily block the detected source IP.

---

## Password spraying flow

Failed login attempts

↓

Track source IP and accounts

↓

**3+ accounts within 60 seconds**

↓

Password spraying detected

↓

Generate alert

↓

Block source IP with UFW