import math
import socket
import struct
import tempfile

from sensor.capture import CaptureSession  # noqa: F401 (live test / sniff smoke)
from sensor.packet import (
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    PacketParseError,
    is_noise,
    parse_packet,
    should_capture,
)
from sensor.flow import Flow, FlowTable
from sensor.extractor import extract_features, feature_vector
from sensor.feature_spec import FEATURE_NAMES
from sensor.normalizer import FeatureNormalizer


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def close(a, b, eps=1e-9):
    return abs(a - b) < eps


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth_frame(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", ethertype) + payload


def ipv4(proto: int, src: str, dst: str, payload: bytes, ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp_pkt(src_port, dst_port, flags, seq=1000, ack=0, payload=b"") -> bytes:
    off_flags = 5 << 4
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, off_flags, flags, 8192, 0, 0)
    pseudo = socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2") + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack("!H", csum(pseudo + hdr + payload)) + hdr[18:]
    return hdr + payload


def udp_pkt(src_port, dst_port, payload=b"x" * 12) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


# ---------- L1 parser ----------

def test_tcp_syn():
    print("test: TCP SYN parse")
    frame = eth_frame(ipv4(IPPROTO_TCP, "10.0.0.1", "10.0.0.2", tcp_pkt(12345, 80, 0x02)))
    p = parse_packet(frame)
    chk(p.protocol == IPPROTO_TCP, "protocol is TCP")
    chk(p.src_ip == "10.0.0.1" and p.dst_ip == "10.0.0.2", "src/dst IP correct")
    chk(p.src_port == 12345 and p.dst_port == 80, "src/dst port correct")
    chk(p.tcp_flags == 0x02 and p.flag_str == "S", "SYN flag set")
    chk(p.l4_len == 0, "no payload")


def test_tcp_ack_data():
    print("test: TCP ACK+data parse")
    payload = b"A" * 50
    frame = eth_frame(ipv4(IPPROTO_TCP, "10.0.0.2", "10.0.0.1", tcp_pkt(80, 12345, 0x10, payload=payload)))
    p = parse_packet(frame)
    chk(p.flag_str == "A", "ACK flag")
    chk(p.l4_len == 50, f"payload length 50, got {p.l4_len}")


def test_udp():
    print("test: UDP parse")
    frame = eth_frame(ipv4(IPPROTO_UDP, "10.0.0.3", "10.0.0.4", udp_pkt(5353, 5353)))
    p = parse_packet(frame)
    chk(p.protocol == IPPROTO_UDP and p.src_port == 5353 and p.dst_port == 5353, "UDP ports")


def test_icmp():
    print("test: ICMP parse")
    frame = eth_frame(ipv4(IPPROTO_ICMP, "10.0.0.1", "10.0.0.2", struct.pack("!BBH", 8, 0, 0)))
    p = parse_packet(frame)
    chk(p.protocol == IPPROTO_ICMP and p.icmp_type == 8, "ICMP echo request")


def test_ipv6():
    print("test: IPv6 parse")
    v6 = struct.pack("!IHBB", 6 << 28, 20, 6, 64)
    v6 += socket.inet_pton(socket.AF_INET6, "2001:db8::1") + socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    v6 += tcp_pkt(4444, 80, 0x02)
    frame = eth_frame(v6, ethertype=0x86DD)
    p = parse_packet(frame)
    chk(p.is_v4 is False and p.src_ip == "2001:db8::1", "IPv6 addresses parsed")
    chk(p.protocol == IPPROTO_TCP and p.dst_port == 80, "IPv6 TCP parsed")


def test_vlan():
    print("test: VLAN tag skipped")
    payload = ipv4(IPPROTO_TCP, "10.0.0.1", "10.0.0.2", tcp_pkt(1, 2, 0x02))
    frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x8100)
    frame += struct.pack("!H", 100) + struct.pack("!H", 0x0800) + payload
    p = parse_packet(frame)
    chk(p.dst_port == 2, "VLAN frame parsed")


def test_filter():
    print("test: protocol + port filtering / noise")
    syn = parse_packet(eth_frame(ipv4(IPPROTO_TCP, "10.0.0.1", "10.0.0.2", tcp_pkt(12345, 80, 0x02))))
    udp = parse_packet(eth_frame(ipv4(IPPROTO_UDP, "10.0.0.1", "10.0.0.2", udp_pkt(1, 1))))
    icmp = parse_packet(eth_frame(ipv4(IPPROTO_ICMP, "10.0.0.1", "10.0.0.2", struct.pack("!BBH", 8, 0, 0))))
    chk(should_capture(syn, include_icmp=False, port_allowlist=None), "TCP passes with no allowlist")
    chk(not should_capture(icmp, include_icmp=False, port_allowlist=None), "ICMP dropped when disabled")
    chk(should_capture(icmp, include_icmp=True, port_allowlist=None), "ICMP passes when enabled")
    chk(should_capture(syn, include_icmp=False, port_allowlist=[80]), "dst port 80 matches allowlist")
    chk(not should_capture(udp, include_icmp=False, port_allowlist=[80]), "port 1 not in allowlist")
    mc = parse_packet(eth_frame(ipv4(IPPROTO_UDP, "10.0.0.1", "224.0.0.251", udp_pkt(5353, 5353))))
    chk(is_noise(mc, drop_link_local=True), "multicast flagged as noise")
    ll = parse_packet(eth_frame(ipv4(IPPROTO_UDP, "169.254.1.1", "10.0.0.2", udp_pkt(1, 1))))
    chk(is_noise(ll, drop_link_local=True), "link-local flagged as noise")
    chk(not is_noise(syn, drop_link_local=True), "normal unicast not noise")


def test_bad_frames():
    print("test: malformed frames rejected")
    for bad in (b"", b"\x00" * 10, eth_frame(b"notanip")):
        try:
            parse_packet(bad)
        except PacketParseError:
            continue
        raise AssertionError(f"FAIL: frame accepted: {bad[:20]!r}")
    print("  ok: malformed frames rejected")


# ---------- L2 flow builder ----------

def tcp_packet(src_ip, src_port, dst_ip, dst_port, flags, ts, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1000, 0, 5 << 4, flags, 8192, 0, 0)
    frame = eth_frame(ipv4(6, src_ip, dst_ip, tcp + payload))
    return parse_packet(frame, ts=ts)


def test_direction_and_flags():
    print("test: forward/backward direction + flag counting")
    ft = FlowTable(idle_timeout=60, active_timeout=300)
    ft.update(tcp_packet("10.0.0.1", 12345, "10.0.0.2", 80, 0x02, ts=0.0), now=0.0)
    ft.update(tcp_packet("10.0.0.2", 80, "10.0.0.1", 12345, 0x12, ts=0.1), now=0.1)
    ft.update(tcp_packet("10.0.0.1", 12345, "10.0.0.2", 80, 0x10, ts=0.2), now=0.2)
    flows = ft.flush_all()
    chk(len(flows) == 1, "all packets grouped into one flow")
    f = flows[0]
    chk(f.fwd_packets == 2 and f.bwd_packets == 1, f"fwd=2 bwd=1, got fwd={f.fwd_packets} bwd={f.bwd_packets}")
    chk(f.syn_count == 2 and f.ack_count == 2, f"syn=2 ack=2, got syn={f.syn_count} ack={f.ack_count}")
    chk(f.fin_count == 0 and f.rst_count == 0, "no FIN/RST seen")
    chk(abs(f.duration - 0.2) < 1e-6, f"duration=0.2s, got {f.duration}")
    chk(f.dst_port == 80, "dst_port is the server port")


def test_multiple_flows():
    print("test: separate flows for separate connections")
    ft = FlowTable()
    for dport in (80, 443, 22):
        ft.update(tcp_packet("10.0.0.1", 30000 + dport, "10.0.0.2", dport, 0x02, ts=0.0), now=0.0)
    flows = ft.flush_all()
    chk(len(flows) == 3, f"three flows created, got {len(flows)}")
    chk(sorted(f.dst_port for f in flows) == [22, 80, 443], "distinct dest ports")


def test_reverse_first_packet_orientation():
    print("test: first packet orientation defines forward")
    ft = FlowTable()
    ft.update(tcp_packet("10.0.0.2", 80, "10.0.0.1", 12345, 0x12, ts=0.0), now=0.0)
    ft.update(tcp_packet("10.0.0.1", 12345, "10.0.0.2", 80, 0x10, ts=0.1), now=0.1)
    f = ft.flush_all()[0]
    chk(f.src_ip == "10.0.0.2" and f.src_port == 80, "first-seen side is forward (server port)")
    chk(f.fwd_packets == 1 and f.bwd_packets == 1, f"each side counted once, got fwd={f.fwd_packets} bwd={f.bwd_packets}")


def test_idle_expiry():
    print("test: idle timeout completes flow")
    ft = FlowTable(idle_timeout=1.0, active_timeout=300)
    ft.update(tcp_packet("10.0.0.1", 1111, "10.0.0.2", 80, 0x02, ts=0.0), now=0.0)
    chk(ft.active_count == 1, "flow active")
    chk(len(ft.expire(now=0.5)) == 0, "not expired at 0.5s (still within idle)")
    chk(len(ft.expire(now=1.5)) == 1, "expired after idle window")
    chk(ft.active_count == 0, "flow removed from table")
    chk(len(ft.expire(now=2.0)) == 0, "nothing left to expire")


def test_active_expiry():
    print("test: active timeout completes chatty flow")
    ft = FlowTable(idle_timeout=60, active_timeout=1.0)
    for t in (0.0, 0.1, 0.2, 0.3):
        ft.update(tcp_packet("10.0.0.1", 2222, "10.0.0.2", 80, 0x10, ts=t), now=t)
    completed = ft.expire(now=1.1)
    chk(len(completed) == 1 and completed[0].total_packets == 4, "completed by active timeout with all packets")


def test_fin_rst_counted():
    print("test: FIN and RST counted")
    ft = FlowTable()
    ft.update(tcp_packet("10.0.0.1", 3333, "10.0.0.2", 80, 0x11, ts=0.0), now=0.0)
    ft.update(tcp_packet("10.0.0.2", 80, "10.0.0.1", 3333, 0x04, ts=0.1), now=0.1)
    f = ft.flush_all()[0]
    chk(f.fin_count == 1 and f.rst_count == 1 and f.ack_count == 1, f"fin=1 rst=1 ack=1, got fin={f.fin_count} rst={f.rst_count} ack={f.ack_count}")


# ---------- L3 feature extraction ----------

def mkflow(duration: float, **overrides) -> Flow:
    params = dict(
        key=("10.0.0.1", "10.0.0.2", 12345, 80, 6),
        protocol=6,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        start_ts=0.0,
        last_ts=duration,
        fwd_packets=4,
        bwd_packets=2,
        fwd_bytes=400,
        bwd_bytes=200,
        syn_count=1,
        ack_count=5,
        fin_count=1,
        rst_count=0,
    )
    params.update(overrides)
    return Flow(**params)


def test_known_values():
    print("test: hand-computed feature values")
    features = extract_features(mkflow(duration=2.0))
    expected = {
        "flow_duration": 2.0, "protocol": 6, "dst_port": 80,
        "total_fwd_packets": 4, "total_bwd_packets": 2,
        "total_fwd_bytes": 400, "total_bwd_bytes": 200,
        "packets_per_second": 3.0, "syn_count": 1, "ack_count": 5, "rst_count": 0,
    }
    for name, want in expected.items():
        chk(close(features[name], want), f"{name} == {want}, got {features[name]}")


def test_zero_duration():
    print("test: zero-duration flow does not break PPS")
    features = extract_features(mkflow(duration=0.0, fwd_packets=2, bwd_packets=0, syn_count=1))
    chk(features["flow_duration"] == 0.0, "raw duration kept as 0.0")
    chk(math.isfinite(features["packets_per_second"]), "PPS is finite (no ZeroDivision)")
    chk(features["packets_per_second"] > 0, f"PPS is positive: {features['packets_per_second']}")


def test_feature_spec():
    print("test: feature spec is 11 ordered features")
    chk(len(FEATURE_NAMES) == 11, f"11 features, got {len(FEATURE_NAMES)}")
    chk(FEATURE_NAMES == [
        "flow_duration", "protocol", "dst_port", "total_fwd_packets",
        "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes",
        "packets_per_second", "syn_count", "ack_count", "rst_count",
    ], "names and order match the plan")
    vec = feature_vector(extract_features(mkflow(duration=1.0)))
    chk(len(vec) == 11 and all(isinstance(v, float) for v in vec), "vector is 11 floats")


def test_normalizer():
    print("test: MinMax normalizer fit/transform/save/load")
    rows = [
        extract_features(mkflow(duration=1.0, fwd_packets=1, syn_count=0)),
        extract_features(mkflow(duration=2.0, fwd_packets=5, syn_count=2)),
        extract_features(mkflow(duration=3.0, fwd_packets=9, syn_count=5)),
    ]
    norm = FeatureNormalizer().fit(rows)
    chk(norm.fitted, "fitted flag set")
    lo = norm.transform(rows[0])
    hi = norm.transform(rows[2])
    chk(lo[3] == 0.0 and hi[3] == 1.0, "min maps to 0, max maps to 1 (fwd_packets)")
    chk(lo[8] == 0.0 and hi[8] == 1.0, "syn_count normalized correctly")
    chk(all(0.0 <= v <= 1.0 for v in lo), "all normalized values within [0,1]")
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=True) as tmp:
        norm.save(tmp.name)
        reloaded = FeatureNormalizer().load(tmp.name)
        chk(close(norm.transform(rows[1])[3], reloaded.transform(rows[1])[3]), "saved scaler reloads identically")


if __name__ == "__main__":
    test_tcp_syn()
    test_tcp_ack_data()
    test_udp()
    test_icmp()
    test_ipv6()
    test_vlan()
    test_filter()
    test_bad_frames()
    test_direction_and_flags()
    test_multiple_flows()
    test_reverse_first_packet_orientation()
    test_idle_expiry()
    test_active_expiry()
    test_fin_rst_counted()
    test_known_values()
    test_zero_duration()
    test_feature_spec()
    test_normalizer()
    print("\nALL SENSOR (L1+L2+L3) TESTS PASSED")
