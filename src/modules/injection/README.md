# Juice Shop Injection Detection and Response

This repository contains the custom Wazuh detection and Active Response
configuration developed for the injection-based security monitoring component.

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
