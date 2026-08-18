import math
import os
import socket
import sys
import threading
import time

from sensor.capture import CaptureSession
from sensor.flow import FlowTable
from sensor.extractor import extract_features
from sensor.feature_spec import FEATURE_NAMES
from sensor.packet import IPPROTO_TCP

DURATION = 6
GEN_SECS = 4
IDLE_TIMEOUT = 1.5


def generate_loopback_traffic(duration: float) -> int:
    end = time.monotonic() + duration
    made = 0
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", 8080), timeout=1) as s:
                s.sendall(b"GET /plan.md HTTP/1.0\r\n\r\n")
                s.recv(1024)
            made += 1
        except OSError:
            pass
        time.sleep(0.05)
    return made


def main() -> int:
    if os.geteuid() != 0:
        print("must run with sudo (root required for raw socket capture)")
        return 2

    gen = threading.Thread(target=generate_loopback_traffic, args=(GEN_SECS,), daemon=True)
    gen.start()

    ft = FlowTable(idle_timeout=IDLE_TIMEOUT, active_timeout=30)
    cap = CaptureSession("lo")
    cap.start()
    started = time.monotonic()
    pkts: list = []
    completed: list = []
    try:
        deadline = time.monotonic() + DURATION
        last_expire = 0.0
        for pkt in cap.packets(timeout=0.2):
            if pkt is None:
                now = time.time()
                if now - last_expire > 0.3:
                    completed.extend(ft.expire(now))
                    last_expire = now
                if time.monotonic() >= deadline:
                    break
                continue
            pkts.append(pkt)
            ft.update(pkt, pkt.ts)
            if pkt.ts - last_expire > 0.3:
                completed.extend(ft.expire(pkt.ts))
                last_expire = pkt.ts
            if time.monotonic() >= deadline:
                break
    finally:
        cap.stop()
    completed.extend(ft.flush_all())
    gen.join(timeout=2)
    elapsed = time.monotonic() - started

    tcp_pkts = [p for p in pkts if p.protocol == IPPROTO_TCP]
    tcp_flows = [f for f in completed if f.protocol == 6]
    healthy = [f for f in tcp_flows if f.fwd_packets >= 2 and f.bwd_packets >= 2]
    feature_rows = [extract_features(f) for f in completed]

    print(f"captured {len(pkts)} packets in {elapsed:.1f}s, {len(tcp_pkts)} TCP")
    print(f"stats: frames={cap.stats.frames_received} parsed={cap.stats.parsed} "
          f"accepted={cap.stats.accepted} noise={cap.stats.noise} filtered={cap.stats.filtered}")
    print(f"flows completed   : {len(completed)}")
    print(f"tcp flows         : {len(tcp_flows)}")
    print(f"tcp flows with fwd>=2 & bwd>=2 : {len(healthy)}")
    print(f"flows with features: {len(feature_rows)}")
    for f in tcp_flows[:4]:
        print(f"  {f.describe()}")
    for row in feature_rows[:6]:
        print("  " + " ".join(f"{row[n]:>12.3f}" for n in FEATURE_NAMES))

    failures = []
    if len(pkts) == 0:
        failures.append("no packets captured")
    if len(tcp_pkts) == 0:
        failures.append("no TCP packets captured")
    if elapsed > DURATION + 2:
        failures.append(f"capture did not stop in time ({elapsed:.1f}s)")
    if len(tcp_flows) < 3:
        failures.append(f"expected >=3 TCP flows, got {len(tcp_flows)}")
    if len(healthy) == 0:
        failures.append("no flow had both directions (fwd>=2 and bwd>=2)")
    if len(feature_rows) < 3:
        failures.append(f"expected >=3 flows with features, got {len(feature_rows)}")
    for i, row in enumerate(feature_rows):
        if len(row) != 11:
            failures.append(f"flow {i}: expected 11 features, got {len(row)}")
            continue
        for name in FEATURE_NAMES:
            if not math.isfinite(row[name]):
                failures.append(f"flow {i}: feature {name} is not finite: {row[name]}")

    if failures:
        for msg in failures:
            print(f"FAIL: {msg}")
        return 1
    print("\nSENSOR (L1+L2+L3) LIVE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
