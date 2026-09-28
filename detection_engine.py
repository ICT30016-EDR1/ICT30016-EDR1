import json
import time
from collections import defaultdict
from scapy.all import sniff, get_if_list, conf, IP, TCP, UDP, ICMP, Raw, Ether

import config
import response_engine

# Per-source-IP, per-attack-type counters
tracker = defaultdict(lambda: {
    'TCP SYN': {'count': 0, 'start': time.time(), 'last_alert': 0},
    'ICMP': {'count': 0, 'start': time.time(), 'last_alert': 0},
    'UDP': {'count': 0, 'start': time.time(), 'last_alert': 0},
    'HTTP Request': {'count': 0, 'start': time.time(), 'last_alert': 0}
})

_packets_seen = 0


def write_raw_alert(attack_type, src_ip, dst_ip, src_mac, dst_mac, iface_name,
                     current_count, pps, alert_msg):
    """Hand a detected flood off to the monitoring engine. This engine has
    no idea what correlation is -- it just appends the raw facts as one
    JSON line for monitoring_engine.py to pick up and enrich."""
    raw = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'artifact_type': attack_type,
        'likely_source_tool': config.LIKELY_SOURCE.get(attack_type, 'unknown -- fill in'),
        'srcip': src_ip,
        'dstip': dst_ip,
        'src_mac': src_mac,
        'dst_mac': dst_mac,
        'interface': iface_name,
        'packet_count': current_count,
        'approx_pps': round(pps, 1),
        'alert_msg': alert_msg,
    }
    with open(config.RAW_ALERTS_FILE, 'a') as f:
        f.write(json.dumps(raw) + '\n')


def detect_floods(packet):
    global _packets_seen
    _packets_seen += 1
    if _packets_seen % 200 == 0:
        print(f"[HEARTBEAT] {_packets_seen} packets reached the callback")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet[Ether].src if Ether in packet else None
        dst_mac = packet[Ether].dst if Ether in packet else None
        iface_name = getattr(packet, 'sniffed_on', None) or config.IFACE
        current_time = time.time()
        attack_type = None

        # 1. Detect ICMP Flood
        if ICMP in packet and packet[ICMP].type == 8:
            attack_type = 'ICMP'
        # 2. Detect UDP Flood
        elif UDP in packet:
            attack_type = 'UDP'
        # 3. Detect TCP SYN Flood & HTTP Requests
        elif TCP in packet:
            # SYN without ACK = a connection attempt (what a flood sends).
            # SYN+ACK = the target's own reply to an accepted connection --
            # without excluding ACK, the victim's legitimate handshake
            # replies get miscounted as it flooding itself.
            if packet[TCP].flags.S and not packet[TCP].flags.A:
                attack_type = 'TCP SYN'
            elif Raw in packet:
                payload = packet[Raw].load
                # startswith, not "in": a request line starts with the verb
                # ("GET /x HTTP/1.1"), a response starts with "HTTP/1.1 200
                # OK" -- matching "in" catches both and misreads replies as
                # incoming requests.
                if payload.startswith((b"GET ", b"POST ", b"HEAD ")):
                    attack_type = 'HTTP Request'

        if attack_type:
            entry = tracker[src_ip][attack_type]

            if current_time - entry['start'] > config.TIME_WINDOW:
                entry['count'] = 1
                entry['start'] = current_time
            else:
                entry['count'] += 1

            current_count = entry['count']
            target_threshold = config.THRESHOLDS[attack_type]

            if current_count % 10 == 0:
                print(f"[DEBUG] {attack_type} from {src_ip}: {current_count}/{target_threshold} pkts")

            # Re-alert on a cooldown for as long as the attack keeps
            # exceeding threshold, instead of once per raw counting window.
            if current_count >= target_threshold and (current_time - entry['last_alert']) >= config.ALERT_COOLDOWN:
                elapsed = current_time - entry['start']
                pps = current_count / elapsed if elapsed > 0 else float(current_count)
                alert_msg = (f"{attack_type} Flood ONGOING from IP: {src_ip}. "
                             f"{current_count} pkts in current window (~{pps:.1f} pkts/sec).")
                print(f"\n🚨 [ALERT TRIGGERED] {alert_msg}\n")
                entry['last_alert'] = current_time
                write_raw_alert(attack_type, src_ip, dst_ip, src_mac, dst_mac, iface_name,
                                 current_count, pps, alert_msg)
                response_engine.respond(attack_type, src_ip)


if __name__ == '__main__':
    print("Starting EDR Detection Engine...")
    print(f"Available interfaces: {get_if_list()}")
    print(f"Sniffing on: {config.IFACE or conf.iface}  <-- confirm this matches where your lab traffic flows")
    print(f"Handing off alerts to: {config.RAW_ALERTS_FILE}")
    print(f"Auto-blocking via iptables directly (no Wazuh in this path) -- actions logged to: {config.RESPONSE_LOG_FILE}\n")

    response_engine.start_response_engine()

    try:
        sniff(filter="ip", prn=detect_floods, store=0, iface=config.IFACE)
    except PermissionError:
        print("Permission denied opening a raw socket -- re-run as root/sudo "
              "(or as Administrator with Npcap on Windows).")
    except OSError as e:
        print(f"Couldn't sniff on interface {config.IFACE!r}: {e}")
