import ipaddress
import struct
import time
from dataclasses import dataclass, field

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_VLAN_QINQ = 0x88A8

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58

PROTO_NAMES = {
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    IPPROTO_ICMP: "ICMP",
    IPPROTO_ICMPV6: "ICMPv6",
}

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


@dataclass
class Packet:
    ts: float
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int
    dst_port: int
    flags: int
    size: int
    l4_len: int
    is_v4: bool = True
    tcp_flags: int = 0
    icmp_type: int = 0
    raw: bytes = field(repr=False, default=b"")

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.protocol, f"IPPROTO_{self.protocol}")

    @property
    def flag_str(self) -> str:
        if self.protocol == IPPROTO_TCP:
            out = []
            if self.tcp_flags & TCP_FIN:
                out.append("F")
            if self.tcp_flags & TCP_SYN:
                out.append("S")
            if self.tcp_flags & TCP_RST:
                out.append("R")
            if self.tcp_flags & TCP_ACK:
                out.append("A")
            return "".join(out)
        if self.protocol in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            return f"type={self.icmp_type}"
        return ""

    def describe(self) -> str:
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
        return f"{self.proto_name:<4} {src} -> {dst} [{self.flag_str}] {self.l4_len}B"


def _is_multicast_or_broadcast(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast:
        return True
    if isinstance(addr, ipaddress.IPv4Address) and addr == ipaddress.IPv4Address("255.255.255.255"):
        return True
    return False


def _is_link_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_link_local


class PacketParseError(Exception):
    pass


def _parse_eth(frame: bytes) -> tuple[int, bytes]:
    if len(frame) < 14:
        raise PacketParseError("truncated ethernet header")
    ethertype = struct.unpack("!H", frame[12:14])[0]
    payload = frame[14:]
    while ethertype in (ETH_P_VLAN, ETH_P_VLAN_QINQ):
        if len(payload) < 4:
            raise PacketParseError("truncated vlan tag")
        ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]
    return ethertype, payload


def _parse_ipv4(buf: bytes) -> tuple[str, str, int, int, int, bytes]:
    if len(buf) < 20:
        raise PacketParseError("truncated ipv4 header")
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        raise PacketParseError("bad ipv4 header length")
    protocol = buf[9]
    total_len = struct.unpack("!H", buf[2:4])[0]
    src_ip = str(ipaddress.IPv4Address(buf[12:16]))
    dst_ip = str(ipaddress.IPv4Address(buf[16:20]))
    payload = buf[ihl:]
    return src_ip, dst_ip, protocol, total_len, ihl, payload


def _parse_ipv6(buf: bytes) -> tuple[str, str, int, int, int, bytes]:
    if len(buf) < 40:
        raise PacketParseError("truncated ipv6 header")
    payload_len = struct.unpack("!H", buf[4:6])[0]
    next_header = buf[6]
    src_ip = str(ipaddress.IPv6Address(buf[8:24]))
    dst_ip = str(ipaddress.IPv6Address(buf[24:40]))
    ihl = 40
    while next_header in (0, 43, 60):  # hop-by-hop, routing, dest-options
        if len(buf) < ihl + 8:
            raise PacketParseError("truncated ipv6 extension header")
        next_header = buf[ihl]
        ext_len = (buf[ihl + 1] + 1) * 8
        ihl += ext_len
    payload = buf[ihl:]
    return src_ip, dst_ip, next_header, ihl + payload_len, ihl, payload


def _parse_tcp(payload: bytes) -> tuple[int, int, int]:
    if len(payload) < 20:
        raise PacketParseError("truncated tcp header")
    src_port, dst_port = struct.unpack("!HH", payload[0:4])
    flags = payload[13]
    data_offset = (payload[12] >> 4) * 4
    if data_offset < 20 or len(payload) < data_offset:
        raise PacketParseError("bad tcp header length")
    return src_port, dst_port, flags


def _parse_udp(payload: bytes) -> tuple[int, int]:
    if len(payload) < 8:
        raise PacketParseError("truncated udp header")
    src_port, dst_port = struct.unpack("!HH", payload[0:4])
    return src_port, dst_port


def _parse_icmp(payload: bytes) -> int:
    if len(payload) < 4:
        raise PacketParseError("truncated icmp header")
    return payload[0]


def _parse_loopback(frame: bytes) -> tuple[int, bytes]:
    """Parse 4-byte loopback header, return (ethertype, ip_payload).
    Linux loopback uses little-endian for the address family."""
    if len(frame) < 4:
        raise PacketParseError("truncated loopback header")
    af = struct.unpack("<I", frame[:4])[0]
    if af == 2:
        return ETH_P_IP, frame[4:]
    if af == 10:
        return ETH_P_IPV6, frame[4:]
    raise PacketParseError(f"unknown loopback address family {af}")


def parse_packet(frame: bytes, ts: float | None = None) -> Packet:
    if ts is None:
        ts = time.time()

    # Detect loopback vs Ethernet:
    #   Loopback: first 4 bytes = address family (2=IPv4, 10=IPv6)
    #   Ethernet: first 6 bytes = dst MAC (first byte LSB bit set for unicast)
    # The key differentiator: loopback AF values (2, 10) are small numbers,
    # while Ethernet dst MAC bytes are typically larger. We check the first
    # 2 bytes: if they match a known loopback AF, treat as loopback.
    try:
        if len(frame) >= 4:
            af = struct.unpack("<I", frame[:4])[0]
            if af == 2 or af == 10:
                ethertype, payload = _parse_loopback(frame)
            else:
                ethertype, payload = _parse_eth(frame)
        else:
            ethertype, payload = _parse_eth(frame)
    except PacketParseError:
        raise PacketParseError("not a recognised frame")

    if ethertype == ETH_P_IP:
        is_v4 = True
        src_ip, dst_ip, protocol, total_len, ihl, l4 = _parse_ipv4(payload)
    elif ethertype == ETH_P_IPV6:
        is_v4 = False
        src_ip, dst_ip, protocol, total_len, ihl, l4 = _parse_ipv6(payload)
    else:
        raise PacketParseError(f"unsupported ethertype 0x{ethertype:04x}")

    src_port = dst_port = 0
    flags = 0
    tcp_flags = 0
    icmp_type = 0
    l4_len = 0

    if protocol == IPPROTO_TCP:
        try:
            src_port, dst_port, tcp_flags = _parse_tcp(l4)
            l4_len = max(0, len(l4) - ((l4[12] >> 4) * 4))
        except PacketParseError:
            src_port = dst_port = -1
    elif protocol == IPPROTO_UDP:
        try:
            src_port, dst_port = _parse_udp(l4)
            l4_len = max(0, len(l4) - 8)
        except PacketParseError:
            src_port = dst_port = -1
    elif protocol in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        try:
            icmp_type = _parse_icmp(l4)
        except PacketParseError:
            icmp_type = -1

    flags = tcp_flags | icmp_type

    return Packet(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        flags=flags,
        size=total_len,
        l4_len=l4_len,
        is_v4=is_v4,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        raw=frame,
    )


def should_capture(pkt: Packet, include_icmp: bool, port_allowlist: list[int] | None) -> bool:
    if pkt.src_port < 0 or pkt.dst_port < 0:
        return False
    if pkt.protocol not in (IPPROTO_TCP, IPPROTO_UDP):
        if not (include_icmp and pkt.protocol in (IPPROTO_ICMP, IPPROTO_ICMPV6)):
            return False
    if port_allowlist:
        if not (pkt.src_port in port_allowlist or pkt.dst_port in port_allowlist):
            return False
    return True


def is_noise(pkt: Packet, drop_link_local: bool) -> bool:
    if _is_multicast_or_broadcast(pkt.src_ip) or _is_multicast_or_broadcast(pkt.dst_ip):
        return True
    if drop_link_local and (_is_link_local(pkt.src_ip) or _is_link_local(pkt.dst_ip)):
        return True
    return False
