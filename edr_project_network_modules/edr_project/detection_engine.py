"""
detection_engine.py -- sniffs for flood-style DoS traffic and hands
detected alerts off to monitoring_engine.py (for Wazuh evidence) and
response_engine.py (for the actual iptables block).

Packet capture here is a raw AF_PACKET socket with hand-rolled struct
parsing, not Scapy. Scapy builds a full layered object graph (Ether/IP/
TCP/UDP/ICMP, every field dissected) for every single packet it sees --
for the handful of fields this script actually reads, that was by far the
biggest CPU cost at flood-level packet rates. parse_packet() below pulls
only those fields directly with struct.unpack, which is dramatically
cheaper per packet. Everything downstream of parsing -- thresholds,
cooldowns, alerting, the self-traffic guard, the response hookup -- is
unchanged from the Scapy version.

Linux-only (AF_PACKET is a Linux socket family), which is fine -- the lab
target is Ubuntu.
"""

import json
import socket
import struct
import time
from collections import defaultdict, namedtuple

import config
import response_engine

ETH_P_IP = 0x0800        # Ethernet type for IPv4
ETH_HEADER_LEN = 14
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

ParsedPacket = namedtuple('ParsedPacket', [
    'src_ip', 'dst_ip', 'src_mac', 'dst_mac',
    'protocol',             # 'ICMP', 'TCP', 'UDP', or None
    'icmp_type',            # set only when protocol == 'ICMP'
    'tcp_syn', 'tcp_ack',   # set only when protocol == 'TCP'
    'payload',              # bytes after the transport header (b'' if none)
])

# Per-source-IP, per-attack-type counters
tracker = defaultdict(lambda: {
    'TCP SYN': {'count': 0, 'start': time.time(), 'last_alert': 0},
    'ICMP': {'count': 0, 'start': time.time(), 'last_alert': 0},
    'UDP': {'count': 0, 'start': time.time(), 'last_alert': 0},
    'HTTP Request': {'count': 0, 'start': time.time(), 'last_alert': 0}
})

_packets_seen = 0


def _format_mac(raw6):
    return ':'.join(f'{b:02x}' for b in raw6)


def parse_packet(frame):
    """Hand-rolled replacement for Scapy's Ether/IP/TCP/UDP/ICMP dissection.
    Returns a ParsedPacket, or None for anything that isn't a plain
    (non-VLAN-tagged) IPv4 frame, or that's too short to safely read --
    same effect as Scapy simply not matching `IP in packet`."""
    if len(frame) < ETH_HEADER_LEN:
        return None

    eth_type = struct.unpack('!H', frame[12:14])[0]
    if eth_type != ETH_P_IP:
        return None

    dst_mac = _format_mac(frame[0:6])
    src_mac = _format_mac(frame[6:12])

    ip = frame[ETH_HEADER_LEN:]
    if len(ip) < 20:
        return None

    ihl = (ip[0] & 0x0F) * 4           # header length is in 32-bit words
    if ihl < 20 or len(ip) < ihl:
        return None

    proto_num = ip[9]
    src_ip = socket.inet_ntoa(ip[12:16])
    dst_ip = socket.inet_ntoa(ip[16:20])
    transport = ip[ihl:]

    if proto_num == PROTO_ICMP:
        if len(transport) < 1:
            return None
        return ParsedPacket(src_ip, dst_ip, src_mac, dst_mac, 'ICMP',
                             transport[0], None, None, transport[8:])

    if proto_num == PROTO_UDP:
        return ParsedPacket(src_ip, dst_ip, src_mac, dst_mac, 'UDP',
                             None, None, None, transport[8:])

    if proto_num == PROTO_TCP:
        if len(transport) < 20:
            return None
        data_offset = (transport[12] >> 4) * 4   # also in 32-bit words
        flags_byte = transport[13]
        tcp_syn = bool(flags_byte & 0x02)
        tcp_ack = bool(flags_byte & 0x10)
        payload = transport[data_offset:]
        return ParsedPacket(src_ip, dst_ip, src_mac, dst_mac, 'TCP',
                             None, tcp_syn, tcp_ack, payload)

    return None  # some other IP protocol (GRE, OSPF, ...) -- not tracked


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


def detect_floods(pkt):
    global _packets_seen
    _packets_seen += 1
    if config.VERBOSE_DEBUG and _packets_seen % 200 == 0:
        print(f"[HEARTBEAT] {_packets_seen} packets reached the callback")

    src_ip = pkt.src_ip
    dst_ip = pkt.dst_ip

    # Never treat this box's own traffic as an attack on itself -- a raw
    # socket sees what this box sends out, not just what it receives.
    if config.LOCAL_IP and src_ip == config.LOCAL_IP:
        return

    current_time = time.time()
    attack_type = None

    # 1. Detect ICMP Flood
    if pkt.protocol == 'ICMP' and pkt.icmp_type == 8:
        attack_type = 'ICMP'
    # 2. Detect UDP Flood
    elif pkt.protocol == 'UDP':
        attack_type = 'UDP'
    # 3. Detect TCP SYN Flood & HTTP Requests
    elif pkt.protocol == 'TCP':
        # SYN without ACK = a connection attempt (what a flood sends).
        # SYN+ACK = the target's own reply to an accepted connection --
        # without excluding ACK, the victim's legitimate handshake
        # replies get miscounted as it flooding itself.
        if pkt.tcp_syn and not pkt.tcp_ack:
            attack_type = 'TCP SYN'
        elif pkt.payload.startswith((b"GET ", b"POST ", b"HEAD ")):
            # startswith, not "in": a request line starts with the verb
            # ("GET /x HTTP/1.1"), a response starts with "HTTP/1.1 200
            # OK" -- matching "in" catches both and misreads replies as
            # incoming requests.
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

        if config.VERBOSE_DEBUG and current_count % 10 == 0:
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
            write_raw_alert(attack_type, src_ip, dst_ip, pkt.src_mac, pkt.dst_mac, config.IFACE,
                             current_count, pps, alert_msg)
            response_engine.respond(attack_type, src_ip)


def _open_capture_socket():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    sock.bind((config.IFACE, 0))
    # Ask the kernel (Linux 4.20+, so fine on Ubuntu 24.04) to never deliver
    # this box's own outgoing packets to this socket at all -- belt-and-
    # suspenders on top of the LOCAL_IP check in detect_floods(). If an
    # older kernel doesn't recognise the option, this just no-ops; the
    # Python-level check still covers correctness either way.
    try:
        ignore_outgoing = getattr(socket, 'PACKET_IGNORE_OUTGOING', 23)
        sol_packet = getattr(socket, 'SOL_PACKET', 263)
        sock.setsockopt(sol_packet, ignore_outgoing, 1)
    except OSError:
        pass
    return sock


if __name__ == '__main__':
    print("Starting EDR Detection Engine...")
    print(f"Available interfaces: {[name for _, name in socket.if_nameindex()]}")
    print(f"Sniffing on: {config.IFACE}  <-- confirm this matches where your lab traffic flows")
    print(f"Handing off alerts to: {config.RAW_ALERTS_FILE}")
    print(f"Auto-blocking via iptables directly (no Wazuh in this path) -- actions logged to: {config.RESPONSE_LOG_FILE}")
    if config.LOCAL_IP:
        print(f"This box's own IP (never counted as an attacker): {config.LOCAL_IP}")
    else:
        print(f"[WARN] Couldn't resolve an IPv4 address for interface {config.IFACE!r} -- "
              f"self-traffic filtering is OFF. The box could flag and block itself again.")
    print(f"Verbose per-packet debug output: {'ON' if config.VERBOSE_DEBUG else 'OFF (set config.VERBOSE_DEBUG = True to enable)'}")
    print("Capturing via raw AF_PACKET socket, IPv4 frames only (kernel-filtered by ethertype)\n")

    response_engine.start_response_engine()

    try:
        sock = _open_capture_socket()
    except PermissionError:
        print("Permission denied opening a raw socket -- re-run as root/sudo.")
        raise SystemExit(1)
    except OSError as e:
        print(f"Couldn't open/bind a raw socket on interface {config.IFACE!r}: {e}")
        raise SystemExit(1)

    try:
        while True:
            frame, _ = sock.recvfrom(65535)
            try:
                pkt = parse_packet(frame)
            except Exception:
                continue  # malformed/truncated frame -- skip, don't crash the sniffer
            if pkt is not None:
                detect_floods(pkt)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        sock.close()
