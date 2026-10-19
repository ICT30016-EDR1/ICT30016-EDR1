# Injection Module – XSS Attack

## Detection engine and Wazuh rules

The Injection module uses Wazuh rules to detect XSS payloads in HTTP requests.

The rules identify common XSS techniques including script elements, iframes, images/SVGs, JavaScript URIs and JavaScript event handlers.

| Wazuh rule | Detection | Level | File | Line |
| --- | --- | --- | --- | --- |
| `100110` | General encoded XSS payload | 10 | `local_rules.xml` | 84–89 |
| `100112` | `<script>` element | 10 | `local_rules.xml` | 92–97 |
| `100113` | `<iframe>` element | 10 | `local_rules.xml` | 100–105 |
| `100114` | `<img>` or `<svg>` element | 10 | `local_rules.xml` | 108–113 |
| `100115` | `javascript:` URI | 10 | `local_rules.xml` | 116–121 |
| `100116` | JavaScript event handlers | 10 | `local_rules.xml` | 124–129 |
| `100111` | XSS followed by HTTP 400/500 response | 12 | `local_rules.xml` | 132–137 |

Rules `100110`–`100116` detect different XSS patterns. Rule `100111` increases the severity when the detected XSS payload is followed by an HTTP 400 or 500 response.

## Response engine

The high-severity XSS rule is connected to the `injection-block` Wazuh Active Response.

| Code | File | Line |
| --- | --- | --- |
| `100111` → `injection-block` | `ossec-injection.conf` | 216–219 |
| `def block_ip(ip):` | `injection-block.py` | 162 |
| `iptables -I INPUT -s ip -j DROP` | `injection-block.py` | 164–175 |

When Rule `100111` is triggered, Wazuh runs the `injection-block.py` Active Response.

The response adds an `iptables` DROP rule for the attacking source IP. The block lasts for 30 seconds.

## XSS attack flow

HTTP request

↓

Wazuh analyses the request

↓

XSS pattern detected

↓

XSS Wazuh rule triggered

↓

HTTP 400/500 response

↓

Rule `100111` – High severity

↓

Wazuh Active Response

↓

Source IP blocked with `iptables`