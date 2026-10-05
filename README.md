# Lightweight Linux EDR System (OWASP Juice Shop Protection)

An extensible, lightweight Python 3 Endpoint Detection and Response (EDR) agent designed to monitor host telemetry, detect web-to-system boundary attacks, and automate threat containment on an Ubuntu Linux environment.

This project is developed for Swinburne's Cybersecurity Lab in collaboration with Robin Poudel (Cythera).

---

## 👥 Team & Workstreams

| Team Member | Role & Workstream | Focus Area |
| :--- | :--- | :--- |
| **Oscar** | Injection Lead | Web-to-system injection vectors |
| **Tyrone** | Malware Lead | Host malware vectors |
| **Aidan** | OS Security Lead | Operating system attacks |
| **Lucas** | Network Security Lead | Network threat research |

---

## 🎯 What We Are Doing

Public-facing applications like **OWASP Juice Shop** often handle untrusted user input without real-time host process visibility. This project bridges that perimeter gap by building a native Python 3 EDR agent that:

* **Monitors Telemetry:** Tails application/system logs (`/var/log/nginx`, `/var/log/auth.log`) and continuously samples process execution trees (`psutil`).

## 📁 Repository File Structure

```text
ICT30016-EDR1/
├── README.md                   # Project overview and documentation (this file)
├── docs/                       # CTI playbooks, architectural diagrams, and research notes
│   ├── cti-playbooks/          # Attack specifications mapped to MITRE ATT&CK
│   └── architecture/           # EDR component design and interface schemas
├── playbooks/                  # Pen-testing attack scripts run from Kali Linux
│   ├── injection_attacks.py    # SQLi, XSS, and Command Injection test payloads
│   ├── malware_simulations.py  # Reverse shell and file drop payloads
│   ├── os_attacks.py           # SSH brute-force and privilege escalation scripts
│   └── network_scans.py        # Port scanning and network probe scripts
└── src/                        # Python 3 EDR Source Code (Starts Phase 4)
    ├── core/                   # Central EDR engine loop and alert dispatcher
    ├── modules/                # Individual workstream monitoring scripts
    │   ├── web_injection.py    # Log parser & process hook for web boundary
    │   ├── malware_monitor.py # FIM & unauthorized process detection
    │   ├── os_monitor.py      # System log auditor & auth monitoring
    │   └── network_monitor.py # Socket auditor & iptables integration
    └── utils/                  # Shared helper tools (logging, system calls)
