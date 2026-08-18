import errno
import queue
import socket
import threading
import time

from core.log import get_logger

from sensor.packet import (
    Packet,
    PacketParseError,
    is_noise,
    parse_packet,
    should_capture,
)

log = get_logger(__name__)


class CaptureStats:
    def __init__(self) -> None:
        self.frames_received = 0
        self.parsed = 0
        self.accepted = 0
        self.parse_errors = 0
        self.filtered = 0
        self.noise = 0


class CaptureSession:
    def __init__(
        self,
        interface: str,
        include_icmp: bool = False,
        port_allowlist: list[int] | None = None,
        drop_link_local: bool = True,
        queue_size: int = 10000,
    ) -> None:
        self.interface = interface
        self.include_icmp = include_icmp
        self.port_allowlist = port_allowlist
        self.drop_link_local = drop_link_local
        self.stats = CaptureStats()
        self._q: queue.Queue[Packet | None] = queue.Queue(maxsize=queue_size)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("capture already started")
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((self.interface, 0))
        sock.settimeout(0.2)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=f"capture-{self.interface}", daemon=True)
        self._thread.start()
        log.info("capture started on interface %s", self.interface)

    def _loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while not self._stop.is_set():
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                if self._stop.is_set():
                    break
                log.error("capture error on %s: %s", self.interface, exc)
                break
            self.stats.frames_received += 1
            try:
                pkt = parse_packet(frame)
            except PacketParseError:
                self.stats.parse_errors += 1
                continue
            self.stats.parsed += 1
            if is_noise(pkt, self.drop_link_local):
                self.stats.noise += 1
                continue
            if not should_capture(pkt, self.include_icmp, self.port_allowlist):
                self.stats.filtered += 1
                continue
            self.stats.accepted += 1
            try:
                self._q.put_nowait(pkt)
            except queue.Full:
                log.warning("capture queue full on %s, dropping packet", self.interface)

    def packets(self, timeout: float = 0.2):
        while True:
            try:
                item = self._q.get(timeout=timeout)
            except queue.Empty:
                if self._stop.is_set():
                    break
                yield None
                continue
            if item is None:
                break
            yield item

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        log.info("capture stopped on interface %s", self.interface)


def sniff(
    interface: str,
    duration: float,
    include_icmp: bool = False,
    port_allowlist: list[int] | None = None,
    drop_link_local: bool = True,
) -> tuple[list[Packet], CaptureStats]:
    cap = CaptureSession(interface, include_icmp, port_allowlist, drop_link_local)
    cap.start()
    deadline = time.monotonic() + duration
    packets: list[Packet] = []
    try:
        gen = cap.packets(timeout=0.1)
        while time.monotonic() < deadline:
            try:
                pkt = next(gen)
            except StopIteration:
                break
            if pkt is None:
                continue
            packets.append(pkt)
            if len(packets) >= 200000:
                break
    finally:
        cap.stop()
    return packets, cap.stats
