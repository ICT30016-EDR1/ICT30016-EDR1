#!/usr/bin/env python3

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime

# ============================================================
# EDR1 LAB TEST HARNESS
#
# Run ONLY on the isolated EDR1 / Juice Shop lab environment.
#
# Juice Shop:
#   192.168.6.4:3000
#
# Kali:
#   192.168.6.1
#
# ============================================================

TARGET = "192.168.6.4"
JUICE_PORT = 3000

KEYLOGGER = "/home/juice/keylogger/keylogger"

INJECTION_LOG = "/var/ossec/logs/injection-incidents.log"
NETWORK_LOG = "/var/log/edr_evidence.jsonl"
MALWARE_LOG = "/var/ossec/logs/alerts/edr_alerts.json"
MALWARE_RESPONSE_LOG = "/var/ossec/logs/alerts/edr_responses.log"
OS_LOG = "/var/log/edr_os_alerts.jsonl"
OS_RESPONSE_LOG = "/var/log/edr_os_response_actions.jsonl"
BRUTE_LOG = "/var/log/edr_bruteforce_alerts.jsonl"
BRUTE_RESPONSE_LOG = "/var/log/edr_bruteforce_response_actions.jsonl"


# ============================================================
# Helpers
# ============================================================

def banner(title):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)
    print()


def run(cmd, check=False):
    print(f"[CMD] {cmd}")

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True,
            timeout=30
        )

        if result.stdout:
            print(result.stdout.strip())

        if result.stderr:
            print(result.stderr.strip())

        if check and result.returncode != 0:
            raise RuntimeError(
                f"Command failed with exit code {result.returncode}"
            )

        return result

    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
        return None


def timestamp():
    return datetime.now().astimezone().isoformat()


def check_file(path):
    exists = os.path.exists(path)

    print(
        f"[{'OK' if exists else 'MISSING'}] "
        f"{path}"
    )

    return exists


def show_evidence(paths, lines=5):
    print()
    print("Evidence check:")
    print("-" * 70)

    for path in paths:
        if not os.path.exists(path):
            print(f"[MISSING] {path}")
            continue

        print()
        print(f"[FILE] {path}")

        try:
            result = subprocess.run(
                ["tail", "-n", str(lines), path],
                text=True,
                capture_output=True,
                timeout=5
            )

            if result.stdout:
                print(result.stdout.strip())

        except Exception as exc:
            print(f"[!] Could not read file: {exc}")


def pause(seconds):
    print()
    print(f"[*] Waiting {seconds} seconds for telemetry...")
    time.sleep(seconds)


# ============================================================
# Injection Module
# ============================================================

def injection_sqli():
    banner("INJECTION - SQL INJECTION")

    print("[*] Sending SQL injection authentication-bypass test.")
    print("[*] Expected high-confidence rule: 100106")
    print()

    cmd = f"""curl -s -i -X POST \
http://{TARGET}:{JUICE_PORT}/rest/user/login \
-H 'Content-Type: application/json' \
--data-binary @- <<'EOF'
{{"email":"' OR 1=1--","password":"test"}}
EOF"""

    run(cmd)

    pause(5)

    show_evidence([
        INJECTION_LOG,
        "/var/ossec/logs/injection-response.log"
    ])


def injection_xss():
    banner("INJECTION - XSS")

    print("[*] Sending benign XSS detection probe.")
    print("[*] Expected high-confidence rule: 100111")
    print()

    cmd = f"""curl -s -i \
-G "http://{TARGET}:{JUICE_PORT}/rest/products/search" \
--data-urlencode "q=<script>alert('EDR1')</script>"
"""

    run(cmd)

    pause(5)

    show_evidence([
        INJECTION_LOG,
        "/var/ossec/logs/injection-response.log"
    ])


def injection_command():
    banner("INJECTION - COMMAND INJECTION")

    print("[*] Sending command-injection detection probe.")
    print("[*] Expected high-confidence rule: 100121")
    print()

    cmd = f"""curl -s -i \
"http://{TARGET}:{JUICE_PORT}/rest/products/search?q=test%3B%20id"
"""

    run(cmd)

    pause(5)

    show_evidence([
        INJECTION_LOG,
        "/var/ossec/logs/injection-response.log"
    ])


def injection_ssti():
    banner("INJECTION - SSTI")

    print("[*] Sending SSTI detection probe.")
    print("[*] Expected high-confidence rule: 100131")
    print()

    cmd = f"""curl -s -i \
"http://{TARGET}:{JUICE_PORT}/rest/products/search?q=%7B%7B7*7%7D%7D"
"""

    run(cmd)

    pause(5)

    show_evidence([
        INJECTION_LOG,
        "/var/ossec/logs/injection-response.log"
    ])


def injection_all():
    banner("INJECTION MODULE - ALL TESTS")

    print("[!] Each high-confidence injection detection can block")
    print("    192.168.6.1 for approximately 60 seconds.")
    print()
    print("[*] Tests will therefore be separated by 65 seconds.")
    print()

    injection_sqli()

    print()
    print("[*] Waiting for injection Active Response timeout...")
    time.sleep(65)

    injection_xss()

    print()
    print("[*] Waiting for injection Active Response timeout...")
    time.sleep(65)

    injection_command()

    print()
    print("[*] Waiting for injection Active Response timeout...")
    time.sleep(65)

    injection_ssti()


# ============================================================
# Network Module
# ============================================================

def network_tcp_syn():
    banner("NETWORK - TCP SYN")

    print("[*] Generating a controlled number of TCP connection attempts.")
    print("[*] This is intentionally kept above the detector threshold")
    print("    but does not attempt a sustained DoS.")
    print()

    # 50 connection attempts.
    for i in range(50):
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.05)

        try:
            sock.connect((TARGET, 3000))
        except Exception:
            pass
        finally:
            sock.close()

    print("[+] TCP test completed.")

    pause(5)

    show_evidence([
        NETWORK_LOG,
        "/var/log/edr_response_actions.log"
    ])


def network_icmp():
    banner("NETWORK - ICMP")

    print("[*] Generating controlled ICMP traffic.")
    print("[*] Detector threshold: 30 packets / 10 seconds.")
    print()

    run(
        f"ping -c 35 -i 0.1 {TARGET}"
    )

    pause(5)

    show_evidence([
        NETWORK_LOG,
        "/var/log/edr_response_actions.log"
    ])


def network_udp():
    banner("NETWORK - UDP")

    print("[*] Generating controlled UDP traffic.")
    print("[*] Detector threshold: 50 packets / 10 seconds.")
    print()

    # Use Python so we don't need a flood tool.
    script = f'''
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for _ in range(55):
    sock.sendto(b"EDR1-LAB-TEST", ("{TARGET}", 9999))
    time.sleep(0.1)

sock.close()
'''

    run(
        "python3 -c " + repr(script)
    )

    pause(5)

    show_evidence([
        NETWORK_LOG,
        "/var/log/edr_response_actions.log"
    ])


def network_http():
    banner("NETWORK - HTTP REQUEST")

    print("[*] Generating controlled HTTP requests.")
    print("[*] Detector threshold: 15 requests / 10 seconds.")
    print()

    for _ in range(20):
        run(
            f"curl -s -o /dev/null "
            f"http://{TARGET}:{JUICE_PORT}/"
        )

    print("[+] HTTP test completed.")

    pause(5)

    show_evidence([
        NETWORK_LOG,
        "/var/log/edr_response_actions.log"
    ])


def network_all():
    banner("NETWORK MODULE - ALL TESTS")

    network_tcp_syn()
    time.sleep(5)

    network_icmp()
    time.sleep(5)

    network_udp()
    time.sleep(5)

    network_http()


# ============================================================
# Malware Module
# ============================================================

def malware_keylogger():
    banner("MALWARE - KEYLOGGER")

    print("[*] Starting the authorised lab keylogger.")
    print()
    print("Expected Wazuh rules:")
    print("  200100 - suspicious keyboard input access")
    print("  200101 - confirmed authorised keylogger executable")
    print()
    print("Expected MITRE:")
    print("  T1056.001")
    print()

    if not os.path.exists(KEYLOGGER):
        print(f"[!] Keylogger not found:")
        print(f"    {KEYLOGGER}")
        return

    process = subprocess.Popen(
        [KEYLOGGER],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print(f"[+] Keylogger started with PID {process.pid}")

    print()
    print("[*] Leave it running for a few seconds so auditd/Wazuh")
    print("    can record the keyboard-device access.")

    time.sleep(8)

    # The EDR response engine should terminate the authorised
    # test keylogger automatically.
    if process.poll() is None:
        print("[*] EDR response has not terminated it yet.")
        print("[*] Stopping the lab process manually.")
        process.terminate()

        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

    print("[+] Keylogger test finished.")

    show_evidence([
        MALWARE_LOG,
        MALWARE_RESPONSE_LOG
    ])


def malware_rootkit():
    banner("MALWARE - ROOTKIT DETECTION TEST")

    print("[*] Testing the Wazuh rootkit rules using logtest.")
    print()
    print("Expected rules:")
    print("  200200 - out-of-tree module")
    print("  200201 - module verification failure")
    print("  200202 - kernel hook")
    print()

    print("[*] Test event 1:")
    print("loading out-of-tree module taints kernel")
    print()

    run(
        "printf '%s\\n' "
        "'loading out-of-tree module taints kernel' "
        "| sudo /var/ossec/bin/wazuh-logtest"
    )


def malware_cryptominer():
    banner("MALWARE - CRYPTOMINER DETECTION TEST")

    print("[*] Testing the cryptominer rules using Wazuh logtest.")
    print()
    print("Expected rules:")
    print("  200300 - RESOURCE_CHECK")
    print("  200301 - MINING_PROCESS")
    print()

    print("[*] RESOURCE_CHECK test:")

    run(
        "printf '%s\\n' "
        "'RESOURCE_CHECK CPU=95 MEMORY=90' "
        "| sudo /var/ossec/bin/wazuh-logtest"
    )

    print()
    print("[*] MINING_PROCESS test:")

    run(
        "printf '%s\\n' "
        "'MINING_PROCESS process=edr1-lab-test' "
        "| sudo /var/ossec/bin/wazuh-logtest"
    )


def malware_all():
    banner("MALWARE MODULE - ALL TESTS")

    malware_keylogger()

    print()
    print("[*] Rootkit rules are tested with Wazuh logtest.")
    malware_rootkit()

    print()
    print("[*] Cryptominer rules are tested with Wazuh logtest.")
    malware_cryptominer()


# ============================================================
# OS Module
# ============================================================

def os_suid():
    banner("OS - SUID PRIVILEGE ESCALATION")

    print("[*] Checking the OS detection agent.")
    print("[*] Expected MITRE: T1548.001")
    print()

    # Generate a harmless SUID artifact on /tmp.
    test_file = "/tmp/edr1_suid_test"

    run(
        f"cp /bin/true {test_file}"
    )

    run(
        f"chmod 4755 {test_file}"
    )

    print()
    print(f"[+] Created controlled SUID test artifact:")
    print(f"    {test_file}")

    run(
        f"ls -l {test_file}"
    )

    print()
    print("[*] Waiting for the OS agent to detect it...")
    time.sleep(10)

    show_evidence([
        OS_LOG,
        OS_RESPONSE_LOG
    ])

    # Cleanup if the response did not already remove it.
    run(
        f"rm -f {test_file}"
    )


def os_cron():
    banner("OS - CRON JOB HIJACKING")

    test_file = "/tmp/edr1_cron_test.sh"

    print("[*] Creating a controlled cron-style test artifact.")
    print()

    with open(test_file, "w") as f:
        f.write("#!/bin/sh\n")
        f.write("echo EDR1_CRON_TEST\n")

    os.chmod(test_file, 0o777)

    print(f"[+] Created:")
    print(f"    {test_file}")

    run(
        f"ls -l {test_file}"
    )

    print()
    print("[*] Waiting for the OS agent to inspect the artifact...")
    time.sleep(10)

    show_evidence([
        OS_LOG,
        OS_RESPONSE_LOG
    ])

    run(
        f"rm -f {test_file}"
    )


def os_all():
    banner("OS MODULE - ALL TESTS")

    os_suid()

    time.sleep(5)

    os_cron()


# ============================================================
# Brute Force Module
# ============================================================

def brute_force_ssh():
    banner("BRUTE FORCE - SSH")

    print("[*] Generating controlled failed SSH authentication attempts.")
    print("[*] Use only against the isolated Juice VM.")
    print()

    # Limited number of failures.
    for i in range(6):
        print(f"[*] Attempt {i + 1}/6")

        run(
            f"ssh "
            f"-o BatchMode=yes "
            f"-o ConnectTimeout=2 "
            f"-o StrictHostKeyChecking=no "
            f"edr1-test-user@{TARGET}"
        )

        time.sleep(1)

    print()
    print("[+] SSH test completed.")

    pause(5)

    show_evidence([
        BRUTE_LOG,
        BRUTE_RESPONSE_LOG
    ])


def brute_force_juice():
    banner("BRUTE FORCE - JUICE SHOP LOGIN")

    print("[*] Generating controlled failed Juice Shop login attempts.")
    print()

    for i in range(6):
        print(f"[*] Login attempt {i + 1}/6")

        cmd = f"""curl -s -o /dev/null -X POST \
http://{TARGET}:{JUICE_PORT}/rest/user/login \
-H 'Content-Type: application/json' \
--data '{{"email":"edr1-test-{i}@example.invalid","password":"incorrect"}}'
"""

        run(cmd)

        time.sleep(1)

    print()
    print("[+] Juice Shop brute-force test completed.")

    pause(5)

    show_evidence([
        BRUTE_LOG,
        BRUTE_RESPONSE_LOG
    ])


def brute_force_all():
    banner("BRUTE FORCE MODULE - ALL TESTS")

    brute_force_ssh()

    time.sleep(5)

    brute_force_juice()


# ============================================================
# Verification
# ============================================================

def verify():
    banner("EDR1 ENVIRONMENT CHECK")

    print("[*] Checking Wazuh...")
    run("systemctl is-active wazuh-manager")

    print()
    print("[*] Checking Juice Shop...")
    run("systemctl is-active juice-shop")

    print()
    print("[*] Checking required logs...")

    paths = [
        INJECTION_LOG,
        NETWORK_LOG,
        MALWARE_LOG,
        MALWARE_RESPONSE_LOG,
        OS_LOG,
        OS_RESPONSE_LOG,
        BRUTE_LOG,
        BRUTE_RESPONSE_LOG
    ]

    for path in paths:
        check_file(path)

    print()
    print("[*] Checking Wazuh configuration...")
    run("sudo /var/ossec/bin/wazuh-analysisd -t")


# ============================================================
# Main menu
# ============================================================

def menu():
    while True:

        banner("EDR1 TEST HARNESS")

        print("1. Injection - SQL Injection")
        print("2. Injection - XSS")
        print("3. Injection - Command Injection")
        print("4. Injection - SSTI")
        print("5. Injection - ALL")
        print()
        print("6. Network - TCP SYN")
        print("7. Network - ICMP")
        print("8. Network - UDP")
        print("9. Network - HTTP")
        print("10. Network - ALL")
        print()
        print("11. Malware - Keylogger")
        print("12. Malware - Rootkit")
        print("13. Malware - Cryptominer")
        print("14. Malware - ALL")
        print()
        print("15. OS - SUID")
        print("16. OS - Cron")
        print("17. OS - ALL")
        print()
        print("18. Brute Force - SSH")
        print("19. Brute Force - Juice Shop")
        print("20. Brute Force - ALL")
        print()
        print("21. Run Environment Check")
        print("0. Exit")
        print()

        choice = input("Select test: ").strip()

        tests = {
            "1": injection_sqli,
            "2": injection_xss,
            "3": injection_command,
            "4": injection_ssti,
            "5": injection_all,

            "6": network_tcp_syn,
            "7": network_icmp,
            "8": network_udp,
            "9": network_http,
            "10": network_all,

            "11": malware_keylogger,
            "12": malware_rootkit,
            "13": malware_cryptominer,
            "14": malware_all,

            "15": os_suid,
            "16": os_cron,
            "17": os_all,

            "18": brute_force_ssh,
            "19": brute_force_juice,
            "20": brute_force_all,

            "21": verify,
        }

        if choice == "0":
            print("Exiting EDR1 test harness.")
            break

        test = tests.get(choice)

        if test is None:
            print("[!] Invalid selection.")
            time.sleep(1)
            continue

        try:
            test()
        except KeyboardInterrupt:
            print()
            print("[!] Test interrupted by user.")
        except Exception as exc:
            print()
            print(f"[!] Test failed: {exc}")

        print()
        input("Press Enter to return to the menu...")


# ============================================================
# Command-line mode
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="EDR1 isolated lab test harness"
    )

    parser.add_argument(
        "--module",
        choices=[
            "injection",
            "network",
            "malware",
            "os",
            "bruteforce",
            "verify"
        ],
        help="Run an entire module without opening the menu."
    )

    args = parser.parse_args()

    if args.module == "injection":
        injection_all()

    elif args.module == "network":
        network_all()

    elif args.module == "malware":
        malware_all()

    elif args.module == "os":
        os_all()

    elif args.module == "bruteforce":
        brute_force_all()

    elif args.module == "verify":
        verify()

    else:
        menu()


if __name__ == "__main__":
    main()