from sensor.flow import Flow
from sensor.feature_spec import FEATURE_NAMES

DURATION_EPSILON = 1e-6


def extract_features(flow: Flow) -> dict:
    duration = flow.duration if flow.duration > DURATION_EPSILON else DURATION_EPSILON
    total_packets = flow.total_packets
    packets_per_second = total_packets / duration
    return {
        "flow_duration": flow.duration,
        "protocol": flow.protocol,
        "dst_port": flow.dst_port,
        "total_fwd_packets": flow.fwd_packets,
        "total_bwd_packets": flow.bwd_packets,
        "total_fwd_bytes": flow.fwd_bytes,
        "total_bwd_bytes": flow.bwd_bytes,
        "packets_per_second": packets_per_second,
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
        "rst_count": flow.rst_count,
    }


def feature_vector(features: dict) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]
