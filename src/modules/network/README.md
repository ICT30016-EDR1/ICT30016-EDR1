# 🌐 Network Security Module — Lightweight Linux EDR

The network detection & response component of the team's **Lightweight Linux EDR**
(OWASP Juice Shop protection). It monitors host network activity, detects network-based
attacks at the web-to-system boundary, and automates containment on Ubuntu Linux.

Part of **ICT30016-EDR1** · Swinburne Cybersecurity Lab (in collaboration with Robin Poudel, Cythera).

---

## 🎯 Purpose

Public-facing apps like Juice Shop expose a host to network-borne follow-on activity. This module
closes the network-visibility gap: it watches the host's live connections and socket activity,
flags suspicious network behaviour, and blocks offending source IPs in real time.

## 🧩 How It Fits

| Location | Responsibility |
| :--- | :--- |
| `src/modules/network_monitor.py` | Socket auditing, detection rules, `iptables` integration |
| `src/core/` | Drives the module and dispatches its alerts |
| `src/utils/` | Shared logging and system-call helpers |

## 🔍 Detection Coverage

| Signal | What it catches | MITRE ATT&CK |
| :--- | :--- | :--- |
| Probe / scan patterns | Port scanning & service enumeration | T1046 Network Service Discovery |
| Repeated failed connections | Network-visible brute-force attempts | T1110 Brute Force |
| Outbound callback traffic | Reverse-shell / C2 beaconing | T1571 Non-Standard Port · T1071 Application Layer Protocol |
| Connections to flagged IPs | Command-and-control channels | TA0011 Command and Control |

## ⚙️ How It Works

1. Inspects host network activity using **native Python sockets** (no Scapy dependency).
2. Evaluates connections against the module's detection rules and thresholds.
3. Logs each event in a simplified, one-line-per-event format.
4. Responds by inserting an **`iptables` DROP** rule for the offending source IP.

## 🧠 Design Decisions (Network workstream)

| Decision | Rationale |
| :--- | :--- |
| Native Python sockets over Scapy | Fewer dependencies, lighter footprint |
| Custom Python response over Wazuh active response | Self-contained and tailored to this EDR |
| Simplified log structure | Faster to parse and review |
| Firewall action: **DROP** (not REJECT) | Silently discards traffic — doesn't reveal the host to the attacker |

## 🚀 Usage

```bash
# via the EDR core (preferred)
sudo python3 -m src.core

# or run the network module directly
sudo python3 -m src.modules.network_monitor --interface eth0
```

Root is required for socket auditing and to apply firewall rules.

## 🧪 Testing

Validated in an **isolated lab VM** against simulated network attacks. The attack simulations live
in `playbooks/` and are for **authorised lab use only** — never run them against systems you do not
own or outside the lab environment.

## ⚠️ Safe Use

Defensive, educational use only. Firewall rules persist until removed — clear any test rules when
finished (or `sudo iptables -F` on a disposable lab VM).

## 👤 Maintainer

**Lucas Callegari** — Network Security Lead
