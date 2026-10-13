# --- Shared configuration -------------------------------------------------
# Used by detection_engine.py, monitoring_engine.py, and response_engine.py.
# Keeping paths, thresholds, and labels in one place means editing one value
# here updates all three, instead of them silently drifting apart.

EVIDENCE_FILE = '/var/log/edr_evidence.jsonl'  # final enriched record -- what Wazuh watches
RAW_ALERTS_FILE = '/var/log/edr_raw_alerts.jsonl'  # detection_engine -> monitoring_engine handoff
# ^ internal only -- not a log anyone reads directly, just the file the two
# processes pass alerts through. The two actual logs are RESPONSE_LOG_FILE
# (below) and EVIDENCE_FILE above; nothing else writes a log file.

IFACE = "ens33"

# This box's own IP on the sniffing interface, resolved once here so
# detection_engine.py and response_engine.py always agree on it.
#
# sniff() on an interface sees outbound traffic too, not just inbound --
# any burst this box sends out itself (DNS lookups, NTP, Wazuh's own agent
# traffic, whatever) has src_ip == this box's own IP, and without a check
# somewhere that gets counted as the box flooding itself. Same root problem
# as the SYN-ACK and HTTP-response mixups fixed earlier in detection_engine.py,
# just unprotected for ICMP/UDP since neither has a flag to tell "sent by
# me" from "received by me". Resolved dynamically instead of hardcoded,
# since the lab IP has already changed once this project (VM snapshot revert).
try:
    from scapy.all import get_if_addr
    LOCAL_IP = get_if_addr(IFACE)
    if not LOCAL_IP or LOCAL_IP == '0.0.0.0':
        LOCAL_IP = None
except Exception:
    LOCAL_IP = None

TIME_WINDOW = 10        # Seconds to measure the threshold limit
ALERT_COOLDOWN = 5      # Seconds between repeat alerts while an attack is ongoing

# Per-packet [DEBUG]/[HEARTBEAT] prints are genuinely useful while watching
# counts climb and confirming detection logic, but at flood-level packet
# rates the prints themselves (terminal writes, happening hundreds of times
# a second) become a real chunk of CPU on top of Scapy's own dissection
# cost. Off by default; flip to True only while actively troubleshooting.
VERBOSE_DEBUG = False

# Thresholds tuned for lab attacks
THRESHOLDS = {
    'TCP SYN': 40,
    'ICMP': 30,
    'UDP': 50,
    # Was 15. The brute force teammate's juice_shop_monitor.py +
    # brute_force_detection.py need to see 3-5 login attempts (within their
    # own 60s window) to correctly classify a credential-stuffing/spraying
    # run -- but at 15 this engine's generic HTTP-request counter crossed
    # first and response_engine.py blocked the source IP via iptables,
    # which cuts the attacker off at the network layer before any further
    # request reaches Juice Shop. The brute force detector never saw enough
    # traffic to fire at all. Raised well above what a lab credential-
    # stuffing demo generates, so that pipeline gets first crack at it; a
    # genuine HTTP flood tool still clears 100 requests in 10s immediately.
    'HTTP Request': 100
}

# Pre-fills the "Source" field in your evidence records -- edit to match
# whatever tool you actually ran for each attack type.
LIKELY_SOURCE = {
    'ICMP': 'hping3',
    'UDP': 'hping3',
    'TCP SYN': 'hping3',
    'HTTP Request': 'slowhttptest',
}

# --- Response engine settings ----------------------------------------------
# response_engine.py blocks with iptables directly -- no Wazuh active-response
# in the loop. BLOCK_TIMEOUT is how long a block lasts (seconds) since the
# most recent alert for that IP before it's auto-lifted; mirrors what Wazuh's
# active-response <timeout> used to do.
BLOCK_TIMEOUT = 600
RESPONSE_LOG_FILE = '/var/log/edr_response_actions.log'

# Which artifact_type values represent a real attacking IP worth blocking,
# vs. a host-local detection with no meaningful srcip to act on. This is the
# same split from TEAM_INTEGRATION.md -- add teammates' types here as their
# detectors come online, if they end up reusing response_engine.py too.
NETWORK_BASED_TYPES = ('TCP SYN', 'ICMP', 'UDP', 'HTTP Request', 'Brute Force', 'SQL Injection')
HOST_BASED_TYPES = ('Malware', 'Privilege Escalation', 'OS Attack')
