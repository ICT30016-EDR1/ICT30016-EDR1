#!/usr/bin/python3

import sys
import json
import subprocess
from datetime import datetime

LOG = "/var/ossec/logs/injection-response.log"


def log(message):
    with open(LOG, "a") as f:
        f.write(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + " "
            + message
            + "\n"
        )


def normalize_ip(ip):
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


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
            ["/usr/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=False
        )


def unblock_ip(ip):
    if iptables_rule_exists(ip):
        subprocess.run(
            ["/usr/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=False
        )


def main():

    # Wazuh sends one JSON message on STDIN
    line = sys.stdin.readline()

    if not line:
        log("ERROR no input received")
        return 1

    try:
        data = json.loads(line)
    except Exception as e:
        log("ERROR invalid JSON: " + str(e))
        return 1

    command = data.get("command", "")

    alert = data.get("parameters", {}).get("alert", {})
    srcip = alert.get("data", {}).get("srcip", "")

    ip = normalize_ip(srcip)

    log(
        "RECEIVED command={} original_ip={} normalized_ip={}".format(
            command, srcip, ip
        )
    )

    if not ip:
        log("ERROR source IP missing")
        return 1

    # Safety
    if ip == "127.0.0.1":
        log("SKIPPED localhost")
        return 0

    if command == "add":

        # Required Wazuh stateful-response handshake
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
            log("ERROR no check_keys response")
            return 1

        try:
            response = json.loads(response_line)
        except Exception as e:
            log("ERROR invalid check_keys response: " + str(e))
            return 1

        response_command = response.get("command", "")

        log("CHECK_KEYS result={}".format(response_command))

        if response_command == "abort":
            log("ABORTED ip={}".format(ip))
            return 0

        if response_command != "continue":
            log(
                "ERROR unexpected check_keys response={}".format(
                    response_command
                )
            )
            return 1

        block_ip(ip)
        log("BLOCKED ip={}".format(ip))

    elif command == "delete":

        unblock_ip(ip)
        log("UNBLOCKED ip={}".format(ip))

    else:
        log("ERROR unknown command={}".format(command))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
