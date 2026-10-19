# Lightweight Linux EDR System
### OWASP Juice Shop Protection & Host-Based Threat Detection

A lightweight and extensible **Python 3 Endpoint Detection and Response (EDR)** system designed for Ubuntu Linux. The project monitors host and application activity, detects security events across multiple attack surfaces, and provides a central platform for demonstrating endpoint detection capabilities.

The project is developed for **Swinburne's Cybersecurity Lab** in collaboration with **Robin Poudel (Cythera)**.

---

## 🎯 Project Overview

Modern web applications such as **OWASP Juice Shop** process large amounts of untrusted user input. While application-level security controls can detect some malicious activity, an attack may continue beyond the application layer and result in suspicious activity on the underlying operating system.

This project addresses that gap by developing a lightweight Linux-based EDR system capable of monitoring and detecting activity across multiple security domains.

The EDR is designed around several independent detection modules:

- 🔐 Brute-force and password-spraying detection
- 💉 Injection and web-attack detection
- 🦠 Malware and suspicious host activity detection
- 🌐 Network attack and traffic monitoring
- 🖥️ Operating-system security monitoring
- 📊 Centralised detection and visualisation through an EDR dashboard

The modular architecture allows individual detection capabilities to be developed, tested, and demonstrated independently while remaining part of a single EDR platform.

---

## 👥 Team & Workstreams

| Team Member | Role & Workstream | Focus Area |
| :--- | :--- | :--- |
| **Oscar** | Injection Lead | Web-to-system injection vectors and injection detection |
| **Tyrone** | Malware Lead | Malware and suspicious host activity |
| **Aidan** | OS Security Lead | Operating-system and authentication attacks |
| **Lucas** | Network Security Lead | Network threats and attack detection |

Each workstream contributes detection logic and testing scenarios to the overall EDR system.

---

## 🛡️ Detection Capabilities

### 🔐 Brute Force & Password Spraying

The brute-force module focuses on identifying repeated authentication attempts and password-spraying behaviour.

Example detection scenarios include:

- Repeated failed authentication attempts
- Password-spraying activity
- Suspicious login patterns
- Authentication attempts originating from unusual sources

The module is intended to help identify attacks against services such as SSH and other authentication mechanisms available on the monitored Linux host.

---

### 💉 Injection Detection

The injection module focuses on attacks where malicious input is introduced through a web-facing application or service.

Detection scenarios include:

- Cross-Site Scripting (XSS)
- Command injection
- Malicious web input
- Web-to-system attack activity

Testing material for the injection workstream is maintained in the `Presentation Demo/` directory.

---

### 🦠 Malware Detection

The malware module focuses on identifying suspicious activity occurring on the Linux host.

Areas of interest include:

- Suspicious processes
- Unexpected files
- Unauthorised file activity
- Malware-like behaviour
- Suspicious execution
- Host-based indicators of compromise

The module is designed to provide visibility into activity that occurs after an attacker gains access to the host.

---

### 🌐 Network Security

The network module monitors network-related activity and supports detection of suspicious network behaviour.

Example scenarios include:

- Network reconnaissance
- Port scanning
- SYN flood activity
- Suspicious connections
- Unexpected network activity

Network attack demonstrations are documented in the `Presentation Demo/` directory.

---

### 🖥️ Operating-System Security

The OS module focuses on security events occurring at the Linux operating-system level.

Areas of interest include:

- Authentication events
- SSH activity
- Failed login attempts
- Privilege-related activity
- Suspicious system behaviour
- Security-relevant operating-system events

---

## 🏗️ System Architecture

The EDR is organised into a central core and a collection of independent detection modules.

```text
                         ┌───────────────────────┐
                         │   Attack / Activity   │
                         │                       │
                         │  Web / Host / Network │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │     Linux Host        │
                         │                       │
                         │  Logs / Processes     │
                         │  Files / Network      │
                         │  Authentication      │
                         └───────────┬───────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │          EDR System             │
                    │                                │
                    │  ┌──────────────────────────┐  │
                    │  │      Detection Modules   │  │
                    │  │                          │  │
                    │  │  Brute Force             │  │
                    │  │  Injection               │  │
                    │  │  Malware                 │  │
                    │  │  Network                 │  │
                    │  │  OS                      │  │
                    │  └────────────┬─────────────┘  │
                    │               │                │
                    │               ▼                │
                    │      Detection / Analysis      │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │   EDR Dashboard       │
                         │                       │
                         │ Alerts / Monitoring   │
                         │ Security Events       │
                         └───────────────────────┘
```

---

## 📁 Repository Structure

The repository is organised into the EDR source code, demonstration material, attack documentation, and project configuration.

```text
ICT30016-EDR1/
│
├── README.md
│   # Project overview and documentation
│
├── LICENSE
│   # MIT License
│
├── Attacks.md
│   # Attack scenarios, testing information and commands
│
├── start.sh
│   # Project startup script
│
├── Presentation Demo/
│   # Demonstration material used during project presentations
│   │
│   ├── Brute Force Module – Password Spraying.md
│   │   # Password-spraying demonstration
│   │
│   ├── Demo Commands.txt
│   │   # Commands used during demonstrations
│   │
│   ├── Injection Module - XSS.md
│   │   # XSS/injection demonstration
│   │
│   └── Network Module – SYN Flood.md
│       # SYN flood/network demonstration
│
└── src/
    # Main Python 3 EDR source code
    │
    ├── core/
    │   # Central EDR components
    │   │
    │   ├── EDR-Test.py
    │   │   # EDR testing and detection runner
    │   │
    │   └── GUI-Dashboard.py
    │       # Graphical EDR monitoring dashboard
    │
    └── modules/
        # Individual EDR detection modules
        │
        ├── brute_force/
        │   # Brute-force and password-spraying detection
        │
        ├── common/
        │   # Shared functionality and utilities
        │
        ├── injection/
        │   # Web and command-injection detection
        │
        ├── malware/
        │   # Malware and suspicious host activity detection
        │
        ├── network/
        │   # Network monitoring and attack detection
        │
        └── os/
            # Operating-system and authentication monitoring
```

---

## 📂 Directory Responsibilities

### `src/core/`

Contains the central components of the EDR system.

| File | Purpose |
| :--- | :--- |
| `EDR-Test.py` | Runs and tests EDR detection functionality |
| `GUI-Dashboard.py` | Provides the graphical dashboard for monitoring EDR activity |

---

### `src/modules/`

Contains the independent detection modules used by the EDR.

| Directory | Purpose |
| :--- | :--- |
| `brute_force/` | Authentication and password-spraying detection |
| `common/` | Shared utilities and functionality |
| `injection/` | Injection and web-attack detection |
| `malware/` | Malware and suspicious host activity detection |
| `network/` | Network monitoring and attack detection |
| `os/` | Operating-system and authentication monitoring |

The modular structure allows each workstream to be developed and tested independently without requiring the entire EDR system to be modified.

---

## 🎬 Presentation Demonstrations

The `Presentation Demo/` directory contains prepared demonstration material used to showcase the capabilities of the EDR system.

Current demonstrations include:

### Brute Force – Password Spraying

Demonstrates authentication attack activity and the corresponding detection capability.

### Injection – XSS

Demonstrates XSS/injection activity against the target environment and the associated detection process.

### Network – SYN Flood

Demonstrates network-based attack activity and the EDR's ability to identify suspicious network behaviour.

### Demo Commands

`Demo Commands.txt` contains the commands required to reproduce the demonstrations in the authorised laboratory environment.

---

## 🧪 Testing Environment

The project is designed for a controlled cybersecurity laboratory environment.

The primary target environment consists of:

```text
┌──────────────────────┐
│      Kali Linux      │
│                      │
│ Attack / Test Tools  │
└──────────┬───────────┘
           │
           │ Controlled Testing
           ▼
┌─────────────────────────────┐
│        Ubuntu Linux         │
│                             │
│     OWASP Juice Shop        │
│             │               │
│             ▼               │
│       Lightweight EDR       │
│             │               │
│             ▼               │
│       EDR Dashboard         │
└─────────────────────────────┘
```

The EDR observes activity generated within the authorised test environment and analyses relevant host and application telemetry.

---

## 🔬 Attack & Detection Workflow

The general testing workflow is:

```text
1. Launch the target environment
              │
              ▼
2. Generate controlled attack activity
              │
              ▼
3. Host/application activity produces telemetry
              │
              ▼
4. EDR detection module analyses activity
              │
              ▼
5. Suspicious behaviour is identified
              │
              ▼
6. Detection event is generated
              │
              ▼
7. Event is presented through the EDR interface
```

This workflow allows attack simulations to be compared against the resulting EDR detections.

---

## 📋 Attack Scenarios

The project currently demonstrates multiple attack categories.

| Attack Category | Detection Module | Demonstration |
| :--- | :--- | :--- |
| Password Spraying | `brute_force/` | Password Spraying |
| XSS / Injection | `injection/` | XSS |
| Malware Activity | `malware/` | Host-based detection |
| SYN Flood | `network/` | SYN Flood |
| OS / Authentication Attacks | `os/` | Operating-system monitoring |

Additional attack scenarios can be incorporated into the modular architecture as the project develops.

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/ICT30016-EDR1/ICT30016-EDR1.git
cd ICT30016-EDR1
```

### 3. Start the EDR

The project includes a startup script:

```bash
chmod +x start.sh
./start.sh
```

The startup process may depend on the configuration of the laboratory environment and the current implementation of the EDR.

### 4. Run the EDR Components

The core EDR components are located in:

```bash
src/core/
```

The detection modules are located in:

```bash
src/modules/
```

Refer to the relevant module and demonstration documentation before running testing activities.

---

## 🖥️ EDR Dashboard

The project includes a graphical dashboard located at:

```text
src/core/GUI-Dashboard.py
```

The dashboard is intended to provide a visual interface for observing EDR activity and security events.

The dashboard complements the detection modules by providing a central location for presenting detected activity.

---

## 🔎 Detection Philosophy

The project follows a modular detection approach.

Rather than relying on a single detection mechanism, the EDR separates detection capabilities into specialised workstreams.

```text
                 ┌─────────────────┐
                 │   Host Events   │
                 └────────┬────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   Authentication     Processes          Network
        │                 │                 │
        ▼                 ▼                 ▼
  Brute Force          Malware          Network
   Detection          Detection        Detection
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                          ▼
                    EDR Analysis
                          │
                          ▼
                     Alert/Event
```

This architecture makes it possible to add or improve individual detection capabilities without redesigning the entire system.

---

## 📚 Documentation

The repository contains several forms of project documentation.

### `Attacks.md`

Contains information relating to attack scenarios and testing commands.

### `Presentation Demo/`

Contains demonstration-specific documentation and commands used when presenting the EDR.

### Source Code

The `src/` directory contains the implementation of the EDR and its detection modules.

---

## 🛠️ Technologies

The project primarily uses:

- **Python 3**
- **Ubuntu Linux**
- **OWASP Juice Shop**
- **Kali Linux** for controlled security testing
- Linux system and security telemetry
- Network monitoring
- Host-based detection techniques
- Graphical monitoring through the EDR dashboard

---

## 🎓 Project Context

This project is developed as part of **Swinburne's Cybersecurity Lab**.

The project focuses on applying practical cybersecurity concepts to the design and implementation of an endpoint detection and response platform.

Key areas of study include:

- Endpoint detection
- Host-based monitoring
- Web-to-system attack detection
- Malware detection
- Network security
- Authentication security
- Security event analysis
- Attack simulation
- Detection engineering
- Cyber threat intelligence

---

## 📈 Future Development

The modular design provides a foundation for future enhancements, including:

- Additional detection rules
- Improved event correlation
- Expanded MITRE ATT&CK mapping
- More comprehensive host telemetry
- Improved dashboard visualisation
- Automated response and containment
- Additional attack simulations
- Improved logging and alert management
- Integration between individual detection modules

---

## ⚠️ Authorised Use

This project is intended for **educational, research, and authorised cybersecurity testing purposes only**.

Attack demonstrations and testing tools must only be executed against systems for which the project team has explicit permission to perform security testing.

Do not use the attack simulations against third-party systems, networks, applications, or infrastructure without appropriate authorisation.

---

## 📄 License

This project is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

---
