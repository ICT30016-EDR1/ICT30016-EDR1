"""
response_engine.py -- automated blocking, performed directly by this EDR
codebase. No Wazuh active-response in the loop for the block itself:
Wazuh still receives the evidence file for alerting/SIEM/reporting exactly
as before (monitoring_engine.py is unchanged), this module just takes the
actual "drop the packets" action out of Wazuh's hands.

detection_engine.py imports this module and:
  - calls start_response_engine() once at startup, to run the auto-unblock
    housekeeping thread in the background
  - calls respond(attack_type, src_ip) at the same point it hands an alert
    off to the monitoring engine

Nothing here runs standalone as a service -- it's a plain function library,
not a script Wazuh's execd invokes. The __main__ block below is only for
manually testing a block from the command line.
"""

import subprocess
import threading
import time

import config

# Wazuh's built-in firewall-drop command checks the <white_list> entries in
# ossec.conf (127.0.0.1, localhost.localdomain, etc.) before blocking. Now
# that this script decides on its own, it needs an equivalent guard --
# otherwise a spoofed or misparsed srcip of 127.0.0.1 would have it drop
# loopback traffic on the box the EDR itself runs on.
#
# config.LOCAL_IP is added too: detection_engine.py already refuses to flag
# its own traffic as an attack in the first place, but this is a second,
# independent layer -- if that guard is ever bypassed by a future bug
# (new attack type, different protocol), this still refuses to actually
# block the box's own IP.
NEVER_BLOCK = {"127.0.0.1", "0.0.0.0"}
if config.LOCAL_IP:
    NEVER_BLOCK.add(config.LOCAL_IP)

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
    """Call this the moment an alert fires. Blocks src_ip if attack_type is
    one worth blocking for -- unless it's already blocked, in which case
    this just extends its timer instead of inserting a duplicate DROP rule.

    A sustained flood re-alerts every ALERT_COOLDOWN seconds (still going,
    not a new attack), so iptables only actually gets touched on the first
    alert for a given IP; every alert after that just keeps the existing
    block alive."""
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
