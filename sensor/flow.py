from dataclasses import dataclass, field

from sensor.packet import (
    PROTO_NAMES,
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    Packet,
)


@dataclass
class Flow:
    key: tuple
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_ts: float
    last_ts: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    first_direction: int = 1  # 1 = (src_ip,src_port) is forward

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    def is_forward(self, pkt: Packet) -> bool | None:
        if pkt.src_ip == self.src_ip and pkt.src_port == self.src_port:
            return True
        if pkt.src_ip == self.dst_ip and pkt.src_port == self.dst_port:
            return False
        return None

    def absorb(self, pkt: Packet, now: float) -> None:
        direction = self.is_forward(pkt)
        if direction is True:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.size
        elif direction is False:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.size
        else:
            return
        self.last_ts = max(self.last_ts, now)
        if pkt.protocol == 6:  # TCP
            if pkt.tcp_flags & TCP_SYN:
                self.syn_count += 1
            if pkt.tcp_flags & TCP_ACK:
                self.ack_count += 1
            if pkt.tcp_flags & TCP_FIN:
                self.fin_count += 1
            if pkt.tcp_flags & TCP_RST:
                self.rst_count += 1

    def describe(self) -> str:
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
        proto = PROTO_NAMES.get(self.protocol, str(self.protocol))
        return (
            f"flow {proto} {src} -> {dst}  "
            f"fwd={self.fwd_packets}p/{self.fwd_bytes}B bwd={self.bwd_packets}p/{self.bwd_bytes}B  "
            f"syn={self.syn_count} ack={self.ack_count} fin={self.fin_count} rst={self.rst_count}  "
            f"dur={self.duration:.2f}s"
        )

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "start_ts": self.start_ts,
            "last_ts": self.last_ts,
            "duration": self.duration,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
        }


def _packet_key(pkt: Packet) -> tuple:
    return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)


def _reverse_key(key: tuple) -> tuple:
    return (key[1], key[0], key[3], key[2], key[4])


class FlowTable:
    def __init__(self, idle_timeout: float = 60.0, active_timeout: float = 300.0) -> None:
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._flows: dict[tuple, Flow] = {}

    @property
    def active_count(self) -> int:
        return len(self._flows)

    def update(self, pkt: Packet, now: float) -> Flow | None:
        if pkt.src_port < 0 or pkt.dst_port < 0:
            return None
        key = _packet_key(pkt)
        flow = self._flows.get(key)
        if flow is None:
            rev = _reverse_key(key)
            flow = self._flows.get(rev)
            if flow is not None and not flow.is_forward(pkt):
                flow.absorb(pkt, now)
                return flow
            flow = Flow(
                key=key,
                protocol=pkt.protocol,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                start_ts=now,
                last_ts=now,
            )
            self._flows[key] = flow
        flow.absorb(pkt, now)
        return flow

    def expire(self, now: float) -> list[Flow]:
        completed = []
        for key in list(self._flows):
            flow = self._flows[key]
            idle = now - flow.last_ts > self.idle_timeout
            active = now - flow.start_ts > self.active_timeout
            if idle or active:
                completed.append(flow)
                del self._flows[key]
        return completed

    def flush_all(self) -> list[Flow]:
        completed = list(self._flows.values())
        self._flows.clear()
        return completed
