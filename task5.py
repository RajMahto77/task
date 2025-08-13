#!/usr/bin/env python3
"""
Educational Packet Sniffer using Scapy.
 """


import argparse
import binascii
import datetime
import signal
import sys
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, conf

# Map protocol numbers/names to human string (partial)
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def hexdump_preview(data: bytes, max_bytes: int = 64) -> str:
    """Return a printable hex + ascii preview of data (max max_bytes)."""
    if not data:
        return "<no payload>"
    preview = data[:max_bytes]
    hex_part = binascii.hexlify(preview).decode('ascii')
    # group hex into pairs
    hex_pairs = ' '.join(hex_part[i:i+2] for i in range(0, len(hex_part), 2))
    # ascii safe
    ascii_part = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in preview)
    more = ' ...' if len(data) > max_bytes else ''
    return f"HEX: {hex_pairs}{more}\nASCII: {ascii_part}{more}"

def format_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

def parse_packet(pkt, show_payload: bool, verbose: bool):
    # Timestamp
    ts = format_ts(pkt.time) if hasattr(pkt, 'time') else "-"
    print("="*80)
    print(f"Time: {ts}")

    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        print(f"Ethernet: src={eth.src} dst={eth.dst} type=0x{eth.type:04x}")

    # IPv4
    if IP in pkt:
        ip = pkt[IP]
        proto = PROTO_MAP.get(ip.proto, str(ip.proto))
        print(f"IP4: src={ip.src} -> dst={ip.dst}  proto={proto}  len={ip.len}")

        # TCP
        if TCP in pkt:
            tcp = pkt[TCP]
            print(f"TCP: sport={tcp.sport} dport={tcp.dport} flags={tcp.flags} seq={tcp.seq} ack={tcp.ack}")
        elif UDP in pkt:
            udp = pkt[UDP]
            print(f"UDP: sport={udp.sport} dport={udp.dport} len={udp.len}")
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            print(f"ICMP: type={icmp.type} code={icmp.code}")

    # IPv6
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        proto = ip6.nh
        print(f"IP6: src={ip6.src} -> dst={ip6.dst}  next_header={proto}")

        if TCP in pkt:
            tcp = pkt[TCP]
            print(f"TCP: sport={tcp.sport} dport={tcp.dport} flags={tcp.flags}")
        elif UDP in pkt:
            udp = pkt[UDP]
            print(f"UDP: sport={udp.sport} dport={udp.dport} len={udp.len}")

    else:
        # Non-IP packet (ARP, etc.)
        print(f"Non-IP packet summary: {pkt.summary()}")

    # Payload (Raw)
    if Raw in pkt:
        raw_payload = bytes(pkt[Raw].load)
        print(f"Payload length: {len(raw_payload)} bytes")
        if show_payload:
            print(hexdump_preview(raw_payload, max_bytes=256))
    else:
        if verbose:
            # in verbose mode, try to show layers and brief info
            print("No Raw payload layer present. Packet layers:", " / ".join(layer.name for layer in pkt.layers()))
    print()  # blank line

def main():
    parser = argparse.ArgumentParser(description="Educational Packet Sniffer (Scapy).")
    parser.add_argument('-i', '--iface', type=str, default=None, help='Interface to sniff (default: scapy default)')
    parser.add_argument('-f', '--filter', type=str, default=None, help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-p', '--payload', action='store_true', help='Show payload preview (hex + ascii)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose: show more packet layer info when available')
    args = parser.parse_args()

    # Informative runtime message
    iface_msg = f"interface={args.iface}" if args.iface else "interface=<scapy default>"
    filter_msg = f'filter="{args.filter}"' if args.filter else 'filter=<none>'
    count_msg = f"count={args.count}" if args.count > 0 else "count=unlimited (Ctrl-C to stop)"
    print(f"Starting sniffer: {iface_msg}  {filter_msg}  {count_msg}")
    print("Press Ctrl-C to stop.\n")

    # Ensure scapy uses provided interface when given
    if args.iface:
        conf.iface = args.iface

    # Graceful stop
    def _stop(signum, frame):
        print("\nStopping capture (signal received). Exiting.")
        sys.exit(0)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    # callback wrapper
    def _handle(pkt):
        try:
            parse_packet(pkt, show_payload=args.payload, verbose=args.verbose)
        except Exception as e:
            print("Error parsing packet:", e)

    # Start sniffing (may require root/admin)
    try:
        sniff(iface=args.iface, filter=args.filter, prn=_handle, store=False, count=args.count if args.count > 0 else 0)
    except PermissionError:
        print("Permission denied: run as root/Administrator.")
    except Exception as e:
        print("Sniffer error:", e)

if __name__ == '__main__':
    main()

