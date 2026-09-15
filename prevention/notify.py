"""Block notifications - notify via Discord webhook when LEON blocks an IP.

Configuration (env vars, see core/config.py):
    LEON_NOTIFY_DISCORD_WEBHOOK   - a Discord channel webhook URL
    LEON_NOTIFY_COOLDOWN          - minimum seconds between notifications (10)

Notifications are opt-out: they activate automatically when the webhook env
var is set, and silently do nothing when it isn't. To avoid flooding the
channel during a DDoS, sends are rate-limited by a cooldown. Every send runs
in a daemon thread and errors are logged, never raised - a slow webhook or a
bad URL can never slow down or crash the pipeline.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from core.config import Config
from core.log import get_logger

log = get_logger(__name__)


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def save_webhook(url: str, path: str | None = None) -> Path:
    """Persist a Discord webhook URL to core/leon.json (gitignored).

    The file (not an env var) is what makes notifications survive ``sudo``:
    superuser can strip environment variables, but never a file on disk.
    """
    if path is None:
        path = str(Path(__file__).resolve().parent.parent / "core" / "leon.json")
    p = Path(path)
    data: dict[str, Any] = {}
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            data = {}
    data["notify_discord_webhook"] = url
    p.write_text(json.dumps(data, indent=2) + "\n")
    log.info("saved webhook URL to %s", p)
    return p


class BlockNotifier:
    """Send a short notification whenever an IP gets blocked."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.cooldown = max(0.0, self.config.notify_cooldown)
        self.webhook = (self.config.notify_discord_webhook or "").strip()
        self._last_sent = 0.0
        self._lock = threading.Lock()
        self._accepted = 0
        self._sent = 0

    @property
    def enabled(self) -> bool:
        return bool(self.webhook)

    def active_channels(self) -> list[str]:
        """Configured notification channels, e.g. ['discord'] or []."""
        return ["discord"] if self.enabled else []

    # ---------- public api ----------

    def send_block_notification(
        self,
        ip: str,
        reason: str | None = None,
        source: str | None = None,
        timeout: float | None = None,
    ) -> bool:
        """Notify that an IP was blocked. Rate-limited; returns True if accepted.

        Compatible with NftablesBlocker's on_block callback signature.
        """
        if not self.enabled:
            return False
        with self._lock:
            now = time.monotonic()
            if now - self._last_sent < self.cooldown:
                log.info("notification rate-limited (cooldown %ss)", self.cooldown)
                return False
            self._last_sent = now
            self._accepted += 1
            self._sent += 1
        threading.Thread(
            target=self._send_async, args=(ip, reason, source, timeout), daemon=True
        ).start()
        return True

    # ---------- internals ----------

    def _send_async(self, ip: str, reason: str | None, source: str | None,
                    timeout: float | None) -> None:
        try:
            self._post_discord(ip, reason, source, timeout)
        except Exception as exc:  # noqa: BLE001 - never crash the pipeline
            log.error("discord notification failed (%s): %s", ip, exc)
            with self._lock:
                self._sent = max(0, self._sent - 1)

    def _post_discord(self, ip: str, reason: str | None, source: str | None,
                      timeout: float | None) -> None:
        payload = json.dumps({"content": self._message(ip, reason, source)}).encode("utf-8")
        req = urllib.request.Request(
            self.webhook,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "LEON-Discord-Notifier/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"discord webhook returned HTTP {resp.status}")
        log.info("discord notification sent for %s", ip)

    @staticmethod
    def _message(ip: str, reason: str | None, source: str | None) -> str:
        lines = [f"**IP BLOCKED:** {ip}"]
        if reason:
            lines.append(f"Reason: {reason}")
        tail = [source, _ts()] if source else [_ts()]
        lines.append("Source: " + " | ".join(t for t in tail if t))
        return "\n".join(lines)


def notify_noop(*args: Any, **kwargs: Any) -> None:
    """Placeholder on_block callback when notifications are disabled."""
    return None