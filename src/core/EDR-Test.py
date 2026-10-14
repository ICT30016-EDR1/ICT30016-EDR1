#!/usr/bin/env python3
"""EDR1 isolated-lab test harness for Injection, Network, Malware, OS and Brute Force."""
import argparse, json, os, shlex, socket, subprocess, sys, time
from datetime import datetime
from pathlib import Path

TARGET = "192.168.6.4"
JUICE_PORT = 3000
JUICE_URL = f"http://{TARGET}:{JUICE_PORT}"
KEYLOGGER = "/home/juice/keylogger/keylogger"
INJECTION_LOG = "/var/ossec/logs/injection-incidents.log"
INJECTION_RESPONSE_LOG = "/var/ossec/logs/injection-response.log"
SECURITY_LOG = "/home/juice/juice-shop/logs/security.log"
ACCESS_LOG = f"/home/juice/juice-shop/logs/access.log.{datetime.now():%Y-%m-%d}"
NETWORK_LOG = "/var/log/edr_evidence.jsonl"
NETWORK_RESPONSE_LOG = "/var/log/edr_response_actions.log"
MALWARE_LOG = "/var/ossec/logs/alerts/edr_alerts.json"
MALWARE_RESPONSE_LOG = "/var/ossec/logs/alerts/edr_responses.log"
OS_LOG = "/var/log/edr_os_alerts.jsonl"
OS_RESPONSE_LOG = "/var/log/edr_os_response_actions.jsonl"
BRUTE_LOG = "/var/log/edr_bruteforce_alerts.jsonl"
BRUTE_RESPONSE_LOG = "/var/log/edr_bruteforce_response_actions.jsonl"
COMMAND_ARTIFACT = "/tmp/injection_test.txt"
SSTI_REQUEST_FILE = "/tmp/edr1_ssti_request.txt"
SSTI_PAYLOAD = "a#{process.binding('fs').readdir('./', {encoding: 'utf-8'}, (err, files) => { if (err) throw err; console.log(files); })}"


def banner(title):
    print("\n" + "=" * 76)
    print(f"  {title}")
    print("=" * 76 + "\n")


def run(command, timeout=30):
    print(f"[CMD] {command}")
    try:
        r = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=timeout)
        if r.stdout.strip(): print(r.stdout.rstrip())
        if r.stderr.strip(): print(r.stderr.rstrip())
        return r
    except subprocess.TimeoutExpired:
        print("[!] Command timed out.")
        return None


def wait(seconds=5):
    print(f"\n[*] Waiting {seconds}s for telemetry...")
    time.sleep(seconds)


def evidence(paths, lines=8):
    print("\n" + "-" * 76 + "\n  EVIDENCE CHECK\n" + "-" * 76)
    for path in paths:
        print(f"\n[FILE] {path}")
        if not os.path.exists(path):
            print("  [MISSING]")
            continue
        print("  [PRESENT]")
        run(f"tail -n {lines} {shlex.quote(path)}", 10)


def require_root():
    if os.geteuid() != 0:
        print("[!] Run this harness with sudo.")
        sys.exit(1)


def verify():
    banner("EDR1 ENVIRONMENT CHECK")
    run("systemctl is-active wazuh-manager")
    run("systemctl is-active juice-shop")
    run("/var/ossec/bin/wazuh-analysisd -t")
    run(f"curl -s -o /dev/null -w '%{{http_code}}\\n' {shlex.quote(JUICE_URL + '/')}")
    for p in [INJECTION_LOG, INJECTION_RESPONSE_LOG, SECURITY_LOG, NETWORK_LOG, MALWARE_LOG,
              MALWARE_RESPONSE_LOG, OS_LOG, OS_RESPONSE_LOG, BRUTE_LOG, BRUTE_RESPONSE_LOG]:
        print(f"[{ 'OK' if os.path.exists(p) else 'MISSING' }] {p}")


# ---------------- Injection ----------------

def injection_sqli():
    banner("INJECTION - SQL INJECTION / AUTHENTICATION BYPASS")
    print("[*] Expected high-confidence Wazuh rule: 100106")
    body = json.dumps({"email": "' OR 1=1--", "password": "password"})
    run(f"curl -s -i -X POST {shlex.quote(JUICE_URL + '/rest/user/login')} -H 'Content-Type: application/json' --data-binary {shlex.quote(body)}")
    wait(); evidence([INJECTION_LOG, INJECTION_RESPONSE_LOG, SECURITY_LOG, ACCESS_LOG])


def injection_xss():
    banner("INJECTION - REFLECTED XSS")
    print("[*] Expected high-confidence Wazuh rule: 100111")
    payload = "<script>alert('XSS_TEST')</script>"
    run(f"curl -s -i -G {shlex.quote(JUICE_URL + '/rest/products/search')} --data-urlencode {shlex.quote('q=' + payload)}")
    wait(); evidence([INJECTION_LOG, INJECTION_RESPONSE_LOG, SECURITY_LOG, ACCESS_LOG])


def injection_command():
    banner("INJECTION - COMMAND INJECTION")
    print("[*] Expected high-confidence Wazuh rule: 100121")
    print(f"[*] Expected artifact: {COMMAND_ARTIFACT}")
    run(f"rm -f {shlex.quote(COMMAND_ARTIFACT)}")
    body = json.dumps({"username": "; whoami > /tmp/injection_test.txt #"})
    run(f"curl -s -i -X POST {shlex.quote(JUICE_URL + '/api/Profile')} -H 'Content-Type: application/json' --data-binary {shlex.quote(body)}")
    print("\n[*] Host artifact verification:")
    if os.path.exists(COMMAND_ARTIFACT):
        print("[+] /tmp/injection_test.txt created")
        run(f"ls -la {shlex.quote(COMMAND_ARTIFACT)}")
        run(f"cat {shlex.quote(COMMAND_ARTIFACT)}")
    else:
        print("[!] /tmp/injection_test.txt was not created.")
    run("ps aux | grep '[n]ode'")
    wait(); evidence([INJECTION_LOG, INJECTION_RESPONSE_LOG, SECURITY_LOG, ACCESS_LOG])


def injection_ssti():
    banner("INJECTION - SSTI")
    print("[*] Expected high-confidence Wazuh rule: 100131")
    print("[*] The project does NOT define a fixed SSTI endpoint; do not use /api/Profile for SSTI.")
    print("[*] Controlled Pug payload:")
    print(SSTI_PAYLOAD)
    print(f"\n[*] Save the exact Burp User Profile request to: {SSTI_REQUEST_FILE}")
    if not os.path.exists(SSTI_REQUEST_FILE):
        print("[!] No saved request found. Capture the normal User Profile request in Burp first.")
        print("    Burp -> Proxy -> HTTP history -> Send to Repeater -> save/copy request.")
        return
    raw = Path(SSTI_REQUEST_FILE).read_text(errors="replace")
    import re
    modified, count = re.subn(r'("username"\s*:\s*)"[^"]*"', lambda m: m.group(1) + json.dumps(SSTI_PAYLOAD), raw, count=1)
    if count:
        out = "/tmp/edr1_ssti_modified_request.txt"
        Path(out).write_text(modified)
        print(f"[+] Modified SSTI artifact generated: {out}")
        print("[!] Replay it in Burp Repeater using the original authenticated request context.")
    else:
        print("[!] Saved request does not contain a JSON username field; modify the actual User Profile parameter in Burp Repeater.")
    wait(); evidence([INJECTION_LOG, INJECTION_RESPONSE_LOG, SECURITY_LOG, ACCESS_LOG])


def injection_all():
    injection_sqli(); print("\n[*] Waiting 65s for injection block timeout..."); time.sleep(65)
    injection_xss(); print("\n[*] Waiting 65s for injection block timeout..."); time.sleep(65)
    injection_command(); print("\n[*] Waiting 65s for injection block timeout..."); time.sleep(65)
    injection_ssti()


# ---------------- Network ----------------

def network_tcp_syn():
    banner("NETWORK - TCP SYN")
    for _ in range(50):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(.05)
        try: s.connect((TARGET, JUICE_PORT))
        except OSError: pass
        finally: s.close()
    wait(); evidence([NETWORK_LOG, NETWORK_RESPONSE_LOG])


def network_icmp():
    banner("NETWORK - ICMP")
    run(f"ping -c 35 -i 0.1 {shlex.quote(TARGET)}")
    wait(); evidence([NETWORK_LOG, NETWORK_RESPONSE_LOG])


def network_udp():
    banner("NETWORK - UDP")
    code = f"import socket,time;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);[(s.sendto(b'EDR1-LAB-TEST',('{TARGET}',9999)),time.sleep(.1)) for _ in range(55)];s.close()"
    run(f"python3 -c {shlex.quote(code)}")
    wait(); evidence([NETWORK_LOG, NETWORK_RESPONSE_LOG])


def network_http():
    banner("NETWORK - HTTP REQUEST")
    for _ in range(20): run(f"curl -s -o /dev/null {shlex.quote(JUICE_URL + '/')}", 5)
    wait(); evidence([NETWORK_LOG, NETWORK_RESPONSE_LOG])


def network_all():
    network_tcp_syn(); time.sleep(5); network_icmp(); time.sleep(5); network_udp(); time.sleep(5); network_http()


# ---------------- Malware ----------------

def malware_keylogger():
    banner("MALWARE - KEYLOGGER")
    print("[*] Expected rules: 200100 / 200101 | MITRE T1056.001")
    if not os.path.exists(KEYLOGGER):
        print(f"[!] Missing {KEYLOGGER}"); return
    p = subprocess.Popen([KEYLOGGER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Started authorised lab keylogger PID={p.pid}")
    time.sleep(8)
    if p.poll() is None:
        print("[*] EDR response has not stopped it; terminating the controlled test process.")
        p.terminate()
        try: p.wait(3)
        except subprocess.TimeoutExpired: p.kill()
    evidence([MALWARE_LOG, MALWARE_RESPONSE_LOG])


def malware_rootkit():
    banner("MALWARE - ROOTKIT RULE TEST")
    for event in ["loading out-of-tree module taints kernel", "module verification failed", "kernel hook detected"]:
        run(f"printf '%s\\n' {shlex.quote(event)} | /var/ossec/bin/wazuh-logtest", 15)


def malware_cryptominer():
    banner("MALWARE - CRYPTOMINER RULE TEST")
    for event in ["RESOURCE_CHECK CPU=95 MEMORY=90", "MINING_PROCESS process=edr1-lab-test"]:
        run(f"printf '%s\\n' {shlex.quote(event)} | /var/ossec/bin/wazuh-logtest", 15)


def malware_all():
    malware_keylogger(); malware_rootkit(); malware_cryptominer()


# ---------------- OS ----------------

def os_suid():
    banner("OS - SUID PRIVILEGE ESCALATION")
    f = "/tmp/edr1_suid_test"
    run(f"cp /bin/true {f}"); run(f"chmod 4755 {f}"); run(f"ls -la {f}")
    wait(10); evidence([OS_LOG, OS_RESPONSE_LOG]); run(f"rm -f {f}")


def os_cron():
    banner("OS - CRON ARTIFACT")
    f = "/tmp/edr1_cron_test.sh"
    Path(f).write_text("#!/bin/sh\necho EDR1_CRON_TEST\n"); os.chmod(f, 0o777)
    run(f"ls -la {f}"); wait(10); evidence([OS_LOG, OS_RESPONSE_LOG]); run(f"rm -f {f}")


def os_all():
    os_suid(); time.sleep(5); os_cron()


# ---------------- Brute force ----------------

def brute_force_ssh():
    banner("BRUTE FORCE - SSH")
    for i in range(6):
        print(f"[*] Attempt {i+1}/6")
        run(f"ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no edr1-test-user@{shlex.quote(TARGET)}", 5)
        time.sleep(1)
    wait(); evidence([BRUTE_LOG, BRUTE_RESPONSE_LOG])


def brute_force_juice():
    banner("BRUTE FORCE - JUICE SHOP CREDENTIAL STUFFING")
    for i in range(6):
        body = json.dumps({"email": f"edr1-test-{i}@example.invalid", "password": "incorrect"})
        run(f"curl -s -o /dev/null -X POST {shlex.quote(JUICE_URL + '/rest/user/login')} -H 'Content-Type: application/json' --data {shlex.quote(body)}", 5)
        time.sleep(1)
    wait(); evidence([BRUTE_LOG, BRUTE_RESPONSE_LOG])


def brute_force_all():
    brute_force_ssh(); time.sleep(5); brute_force_juice()


# ---------------- CLI/menu ----------------

def main():
    global SSTI_REQUEST_FILE
    require_root()
    parser = argparse.ArgumentParser(description="EDR1 isolated-lab test harness")
    parser.add_argument("--module", choices=["injection","network","malware","os","bruteforce","verify"])
    parser.add_argument("--ssti-request", default=SSTI_REQUEST_FILE)
    args = parser.parse_args()
    SSTI_REQUEST_FILE = args.ssti_request

    funcs = {
        "injection": injection_all, "network": network_all, "malware": malware_all,
        "os": os_all, "bruteforce": brute_force_all, "verify": verify,
    }
    if args.module:
        funcs[args.module](); return

    menu = [
        ("1","Injection - SQL Injection",injection_sqli),("2","Injection - XSS",injection_xss),
        ("3","Injection - Command Injection",injection_command),("4","Injection - SSTI",injection_ssti),
        ("5","Injection - ALL",injection_all),("6","Network - TCP SYN",network_tcp_syn),
        ("7","Network - ICMP",network_icmp),("8","Network - UDP",network_udp),
        ("9","Network - HTTP",network_http),("10","Network - ALL",network_all),
        ("11","Malware - Keylogger",malware_keylogger),("12","Malware - Rootkit",malware_rootkit),
        ("13","Malware - Cryptominer",malware_cryptominer),("14","Malware - ALL",malware_all),
        ("15","OS - SUID",os_suid),("16","OS - Cron",os_cron),("17","OS - ALL",os_all),
        ("18","Brute Force - SSH",brute_force_ssh),("19","Brute Force - Juice Shop",brute_force_juice),
        ("20","Brute Force - ALL",brute_force_all),("21","Environment Check",verify),
    ]
    while True:
        banner("EDR1 TEST HARNESS")
        for n,name,_ in menu: print(f"{n:>2}. {name}")
        print(" 0. Exit\n")
        choice=input("Select test: ").strip()
        if choice=="0": return
        selected=next((x for x in menu if x[0]==choice),None)
        if not selected:
            print("[!] Invalid selection."); continue
        try: selected[2]()
        except KeyboardInterrupt: print("\n[!] Test interrupted.")
        except Exception as e: print(f"\n[!] Test error: {e}")
        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()
