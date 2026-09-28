import subprocess
import threading
import time

import config

NEVER_BLOCK = {"127.0.0.1", "0.0.0.0"}

_lock = threading.Lock()
_blocked = {}  # srcip -> time.time() of its most recent (re-)block


def _log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with open(config.RESPONSE_LOG_FILE, 'a') as f:
        f.write(line + '\n')
    print(f"[RESPONSE] {msg}")


def block_ip(ip):
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)


def unblock_ip(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)


def respond(attack_type, src_ip):
    if not src_ip or src_ip in NEVER_BLOCK:
        if src_ip in NEVER_BLOCK:
            _log(f"Refusing to block whitelisted/invalid IP: {src_ip} (artifact_type={attack_type})")
        return

    if attack_type not in config.NETWORK_BASED_TYPES:
        if attack_type in config.HOST_BASED_TYPES:
            _log(f"{attack_type} alert received -- no automated action defined yet, logging only")
        else:
            _log(f"Unrecognized artifact_type '{attack_type}' -- logging only, no action taken")
        return

    with _lock:
        already_blocked = src_ip in _blocked
        _blocked[src_ip] = time.time()

    if already_blocked:
        return  # still ongoing -- timer extended above, no need to re-block

    block_ip(src_ip)
    _log(f"BLOCKED {src_ip} (artifact_type={attack_type}, auto-unblocks after "
         f"{config.BLOCK_TIMEOUT}s of no further alerts)")


def _expire_loop():
    """Background housekeeping: wakes up periodically and unblocks any IP
    whose BLOCK_TIMEOUT has elapsed since its last (re-)block -- the same
    job Wazuh's active-response <timeout> used to do."""
    while True:
        time.sleep(5)
        now = time.time()
        expired = []
        with _lock:
            for ip, blocked_at in list(_blocked.items()):
                if now - blocked_at >= config.BLOCK_TIMEOUT:
                    expired.append(ip)
                    del _blocked[ip]
        for ip in expired:
            unblock_ip(ip)
            _log(f"UNBLOCKED {ip} (no alerts for {config.BLOCK_TIMEOUT}s -- timeout reached)")


def start_response_engine():
    """Call once at startup, before sniff() starts. Runs the auto-unblock
    sweep on a daemon thread so respond() never has to block packet
    processing waiting on its own timeout logic."""
    threading.Thread(target=_expire_loop, daemon=True).start()
    _log("Response engine started")


if __name__ == '__main__':
    # Manual test, independent of the sniffer:
    #   sudo python3 response_engine.py <ip> [attack_type]
    import sys
    if len(sys.argv) < 2:
        print("Usage: sudo python3 response_engine.py <ip> [attack_type]")
        sys.exit(1)
    test_ip = sys.argv[1]
    test_type = sys.argv[2] if len(sys.argv) > 2 else 'TCP SYN'
    print(f"Testing respond({test_type!r}, {test_ip!r})...")
    respond(test_type, test_ip)
    print(f"Currently tracked as blocked: {list(_blocked.keys())}")
    print("Check with: sudo iptables -L INPUT -n")
