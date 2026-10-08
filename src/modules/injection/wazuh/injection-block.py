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
        ["/usr/sbin/iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
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

    alert = data.get("parameters", {}).get("alert", {})

    alert_data = alert.get("data", {})

    srcip = alert_data.get("srcip", "")

    ip = normalize_ip(srcip)

    rule_id = str(alert.get("rule", {}).get("id", ""))

    rule_description = alert.get("rule", {}).get("description", "")

    attack_type = get_attack_type(rule_id)

    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    log_response(
        "RECEIVED command={} rule={} attack={} "
        "original_ip={} normalized_ip={}".format(
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

        print(json.dumps(check_message), flush=True)

        response_line = sys.stdin.readline()

        if not response_line:
            log_response("ERROR no check_keys response")
            return 1

        try:
            response = json.loads(response_line)
        except Exception as e:
            log_response(
                "ERROR invalid check_keys response: " + str(e)
            )
            return 1

        response_command = response.get("command", "")

        log_response(
            "CHECK_KEYS result={}".format(response_command)
        )

        if response_command == "abort":

            log_response("ABORTED ip={}".format(ip))

            return 0

        if response_command != "continue":

            log_response(
                "ERROR unexpected check_keys response={}".format(
                    response_command
                )
            )

            return 1

        # Create incident record

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

        # Contain source IP

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
            "ERROR unknown command={}".format(command)
        )

        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
