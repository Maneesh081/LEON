"""L7 - active honeypot: a decoy TCP listener that turns any connection into
a deterministic attacker signal.

Real users never connect to a port that runs no service, so any probe is a
scan attempt. On connection we:

  1. log + emit a honeypot.probe event,
  2. hold the socket open for honeypot_dwell_secs to waste the attacker's time,
  3. call on_probe(peer_ip) so the caller can feed a synthetic ANOMALY verdict
     into the DecisionEngine and block the attacker.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable

from core.config import Config
from core.events import EventStore
from core.log import get_logger

log = get_logger(__name__)


class Honeypot:
    def __init__(self, config: Config | None = None, store: EventStore | None = None,
                 on_probe: Callable[[str], None] | None = None) -> None:
        self.config = config or Config()
        self.store = store or EventStore()
        self.on_probe = on_probe
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        for port in self.config.honeypot_ports:
            thread = threading.Thread(target=self._listen, args=(port,),
                                      name=f"honeypot-{port}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=2.0)

    def _listen(self, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(8)
            sock.settimeout(0.5)
        except OSError as exc:
            log.error("honeypot: cannot bind port %d: %s", port, exc)
            return
        self._sockets.append(sock)
        log.info("honeypot listening on port %d", port)
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr),
                             name="honeypot-conn", daemon=True).start()

    def _handle(self, conn: socket.socket, addr: tuple) -> None:
        peer = addr[0]
        port = conn.getsockname()[1]
        log.info("honeypot probe from %s", peer)
        self.store.emit("L7", "honeypot.probe", ip=peer, port=port)
        self._dwell(conn)
        if self.on_probe is not None:
            try:
                self.on_probe(peer)
            except Exception as exc:  # noqa: BLE001 - never kill the listener
                log.error("honeypot on_probe failed: %s", exc)

    def _dwell(self, conn: socket.socket) -> None:
        """Keep the connection open to slow the attacker down."""
        dwell = self.config.honeypot_dwell_secs
        deadline = time.monotonic() + dwell
        try:
            conn.settimeout(0.5)
            while time.monotonic() < deadline:
                try:
                    data = conn.recv(1024)
                    if not data:
                        return
                except socket.timeout:
                    continue
                except OSError:
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass
