FEATURE_NAMES = [
    "flow_duration",
    "protocol",
    "dst_port",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packets_per_second",
    "syn_count",
    "ack_count",
    "rst_count",
]

# Raw cleaned CSVs use the teammate's column names; map to our sensor contract.
# Single source of truth, shared by training (model/train_compare.py) and the
# dashboard dataset view (dashboard/server.py).
CSV_COLUMN_MAP = {
    "flow_duration": "flow_duration",
    "protocol": "protocol",
    "dst_port": "destination_port",
    "total_fwd_packets": "forward_packet_count",
    "total_bwd_packets": "backward_packet_count",
    "total_fwd_bytes": "forward_bytes",
    "total_bwd_bytes": "backward_bytes",
    "packets_per_second": "packets_per_second",
    "syn_count": "syn_count",
    "ack_count": "ack_count",
    "rst_count": "rst_count",
}

LABELS = [
    "BENIGN",
    "DoS",
    "DDoS",
    "PortScan",
    "BruteForce",
]

assert len(FEATURE_NAMES) == 11
assert set(CSV_COLUMN_MAP) == set(FEATURE_NAMES)
