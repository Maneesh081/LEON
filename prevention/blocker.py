"""L7 - nftables IPS blocker.

Owns two dedicated tables (``ip leon`` and ``ip6 leon``) with timeout-enabled
named sets. Blocks are isolated to those tables and never touch the user's
other nftables rules. Requires root - the whole LEON process runs under sudo.

Table layout:

    table ip leon {
      set blocked { type ipv4_addr; flags timeout; }
      chain input { type filter hook input priority 0; policy accept;
                    ip saddr @blocked drop; }
    }

Blocks are persisted to config.blocks_file so a restart can re-apply any
not-yet-expired blocks (nftables sets do not survive a reboot).
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
from pathlib import Path

from core.config import Config
from core.log import get_logger

log = get_logger(__name__)

NFT = "nft"
TABLE = "leon"
CHAIN = "input"
IP_TOKEN = re.compile(r"[0-9a-fA-F:.\-]+")


class NftablesError(Exception):
    pass


class NftablesBlocker:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.blocks_file = Path(self.config.blocks_file)
        self._blocks: dict[str, dict] = {}  # ip -> {blocked_at, expires_at|None}

    # ---------- low-level ----------

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        proc = subprocess.run([NFT, *args], capture_output=True, text=True)
        if proc.returncode != 0:
            raise NftablesError(f"nft {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc

    def _add_ignore_exists(self, *args: str) -> None:
        proc = subprocess.run([NFT, *args], capture_output=True, text=True)
        if proc.returncode != 0 and "File exists" not in proc.stderr:
            raise NftablesError(f"nft {' '.join(args)} failed: {proc.stderr.strip()}")

    @staticmethod
    def _family_for(ip: str) -> str:
        try:
            return "ip" if ipaddress.ip_address(ip).version == 4 else "ip6"
        except ValueError as exc:
            raise NftablesError(f"not a valid IP address: {ip}") from exc

    @staticmethod
    def _set_name(family: str) -> str:
        return "blocked" if family == "ip" else "blocked6"

    # ---------- lifecycle ----------

    def ensure(self) -> None:
        """Create our tables/sets/chains/rules idempotently."""
        for family in ("ip", "ip6"):
            set_name = self._set_name(family)
            addr_type = "ipv4_addr" if family == "ip" else "ipv6_addr"
            saddr = "ip" if family == "ip" else "ip6"
            self._add_ignore_exists("add", "table", family, TABLE)
            self._add_ignore_exists(
                "add", "set", family, TABLE, set_name,
                f"{{ type {addr_type}; flags timeout; }}")
            self._add_ignore_exists(
                "add", "chain", family, TABLE, CHAIN,
                "{ type filter hook input priority 0; policy accept; }")
            self._add_ignore_exists(
                "add", "rule", family, TABLE, CHAIN, f"{saddr} saddr @{set_name} drop")

    def teardown(self) -> None:
        """Delete our tables (test cleanup / full reset)."""
        for family in ("ip", "ip6"):
            try:
                self._run("delete", "table", family, TABLE)
            except NftablesError:
                pass
        self._blocks.clear()
        self._save()

    # ---------- operations ----------

    def block(self, ip: str, timeout: float | None = None) -> bool:
        if timeout is None:
            timeout = self.config.block_timeout
        self.ensure()
        family = self._family_for(ip)
        element = f"{{ {ip}"
        if timeout and timeout > 0:
            element += f" timeout {int(timeout)}s"
        element += " }"
        self._run("add", "element", family, TABLE, self._set_name(family), element)
        expires_at = time.time() + timeout if timeout and timeout > 0 else None
        self._blocks[ip] = {"blocked_at": time.time(), "expires_at": expires_at}
        self._save()
        log.info("blocked %s (timeout=%ss)", ip, int(timeout) if timeout else "permanent")
        return True

    def unblock(self, ip: str) -> bool:
        self.ensure()
        family = self._family_for(ip)
        try:
            self._run("delete", "element", family, TABLE, self._set_name(family), f"{{ {ip} }}")
        except NftablesError:
            log.info("unblock %s: not present", ip)
            self._blocks.pop(ip, None)
            self._save()
            return False
        self._blocks.pop(ip, None)
        self._save()
        log.info("unblocked %s", ip)
        return True

    def list_blocked(self) -> list[str]:
        ips: list[str] = []
        for family in ("ip", "ip6"):
            try:
                proc = self._run("list", "set", family, TABLE, self._set_name(family))
            except NftablesError:
                continue
            for tok in IP_TOKEN.findall(proc.stdout):
                if "." in tok or ":" in tok:
                    ips.append(tok)
        return sorted(set(ips))

    # ---------- persistence ----------

    def restore(self) -> int:
        """Re-apply unexpired blocks from config.blocks_file. Returns count."""
        if not self.blocks_file.exists():
            return 0
        try:
            data = json.loads(self.blocks_file.read_text())
        except json.JSONDecodeError:
            log.warning("blocks file corrupt: %s", self.blocks_file)
            return 0
        now = time.time()
        restored = 0
        for ip, rec in data.items():
            expires_at = rec.get("expires_at")
            if expires_at is not None and now >= expires_at:
                continue
            remaining = None
            if expires_at is not None:
                remaining = max(0.0, expires_at - now)
            try:
                self.block(ip, timeout=remaining)
                restored += 1
            except NftablesError as exc:
                log.warning("restore block %s failed: %s", ip, exc)
        return restored

    def _save(self) -> None:
        self.blocks_file.parent.mkdir(parents=True, exist_ok=True)
        self.blocks_file.write_text(json.dumps(self._blocks, indent=2) + "\n")
