# Network Module – SYN Flood

## Detection engine and config

Checks network traffic and counts SYN packets from each source IP.

| Code lines | file | line |
| --- | --- | --- |
| `THRESHOLDS = {"TCP SYN": 40, "ICMP": 30, "UDP": 50, "HTTP Request": 100}` | config.py | 72 |
| `TIME_WINDOW = 10` | config.py | 61 |
| `if tcp_flags & 0x02 and not (tcp_flags & 0x10):` | detection_engine.py | 161 |
| `if count >= THRESHOLDS[attack_type]:` | detection_engine.py | 173 |
| `write_raw_alert(attack_type, src_ip, packet_count, pps)` | detection_engine.py | 115 |
| `response_engine.respond(attack_type, src_ip)` | detection_engine.py | 63 |

The module detects a SYN flood when **40 SYN packets** are received from one source within **10 seconds**.

---

## Response engine

Blocks the IP address responsible for the SYN flood.

| Code lines | file | line |
| --- | --- | --- |
| `def block_ip(ip):` | response_engine.py | 55 |
| `subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)` | response_engine.py | 55 |
| `respond(attack_type, src_ip)` | response_engine.py | 63 |

The response engine adds an iptables rule to drop traffic from the detected IP.

The block lasts for **30 seconds**.

---

## SYN flood flow

SYN packets

↓

Count packets from source IP

↓

**40 packets in 10 seconds**

↓

Generate alert

↓

Send IP to response engine

↓

Block IP with iptables