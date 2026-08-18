import argparse
import sys
import time

from core.config import load_config
from core.events import EventStore
from core.log import get_logger

from sensor.capture import CaptureSession
from sensor.flow import FlowTable
from sensor.extractor import extract_features, feature_vector
from sensor.feature_spec import FEATURE_NAMES
from sensor.normalizer import FeatureNormalizer

log = get_logger(__name__)


def main() -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        prog="run_sensor", description="LEON sensor: L1 packet capture -> L2 flows -> L3 features")
    parser.add_argument("-i", "--interface", default=None, help="interface to capture on (default: all configured)")
    parser.add_argument("-d", "--duration", type=float, default=10.0, help="capture duration in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="print per-flow features")
    parser.add_argument("--icmp", action="store_true", help=f"include ICMP (config default: {cfg.include_icmp})")
    parser.add_argument("--idle", type=float, default=cfg.flow_idle_timeout, help=f"idle timeout (default {cfg.flow_idle_timeout})")
    parser.add_argument("--active", type=float, default=cfg.flow_active_timeout, help=f"active timeout (default {cfg.flow_active_timeout})")
    parser.add_argument("--stage", choices=("capture", "flow", "features"), default="features",
                        help="how far down the pipeline to report (default: features)")
    args = parser.parse_args()

    interfaces = [args.interface] if args.interface else cfg.interfaces
    include_icmp = args.icmp or cfg.include_icmp

    ft = FlowTable(idle_timeout=args.idle, active_timeout=args.active)
    store = EventStore()
    flow_rows: list[dict] = []
    packets: list = []

    log.info("LEON sensor starting (stage=%s)", args.stage)

    def emit(flow) -> None:
        features = extract_features(flow)
        flow_rows.append(features)
        store.emit("SENSOR", "flow.features", flow=flow.to_dict(), features=features)
        if args.verbose:
            print(f"  [features] {flow.describe()}")

    for iface in interfaces:
        cap = CaptureSession(iface, include_icmp, cfg.port_allowlist, cfg.drop_link_local)
        try:
            cap.start()
        except PermissionError:
            log.error("permission denied on %s - run with sudo (root is required for raw sockets)", iface)
            return 2
        except OSError as exc:
            log.error("cannot capture on %s: %s", iface, exc)
            continue

        deadline = time.monotonic() + args.duration
        last_expire = 0.0
        try:
            for pkt in cap.packets(timeout=0.2):
                if pkt is None:
                    now = time.time()
                    if now - last_expire > 0.5:
                        for flow in ft.expire(now):
                            emit(flow)
                        last_expire = now
                    if time.monotonic() >= deadline:
                        break
                    continue
                packets.append(pkt)
                ft.update(pkt, pkt.ts)
                if pkt.ts - last_expire > 0.5:
                    for flow in ft.expire(pkt.ts):
                        emit(flow)
                    last_expire = pkt.ts
                if time.monotonic() >= deadline:
                    break
        finally:
            cap.stop()
        if args.stage == "capture":
            print(f"\n===== L1 CAPTURE SUMMARY [{iface}] =====")
            print(f"frames received : {cap.stats.frames_received}")
            print(f"packets accepted: {cap.stats.accepted}")
            print(f"filtered/noise  : {cap.stats.filtered + cap.stats.noise}")
            print(f"parse errors    : {cap.stats.parse_errors}")
        elif args.stage == "flow":
            print(f"\n===== L2 FLOW SUMMARY [{iface}] =====")
            print(f"flows emitted   : {len(flow_rows)}")

    for flow in ft.flush_all():
        emit(flow)

    print("\n===== SENSOR SUMMARY =====")
    print(f"packets captured: {len(packets)}")
    print(f"flows with features : {len(flow_rows)}")

    if flow_rows:
        norm = FeatureNormalizer().fit(flow_rows)
        print("\n--- first 6 flows: raw features ---")
        hdr = " ".join(f"{n:>18}" for n in FEATURE_NAMES)
        print(hdr)
        for row in flow_rows[:6]:
            print(" ".join(f"{feature_vector(row)[i]:>18.3f}" for i in range(11)))
        print("\n--- first 6 flows: normalized [0,1] ---")
        print(hdr)
        for vec in norm.transform_many(flow_rows[:6]):
            print(" ".join(f"{v:>18.3f}" for v in vec))
    return 0


if __name__ == "__main__":
    sys.exit(main())
