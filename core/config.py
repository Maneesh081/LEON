import json
import os
import sys
from pathlib import Path

from core.log import get_logger

log = get_logger(__name__)


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_ports(name: str) -> list[int] | None:
    v = os.environ.get(name)
    if not v:
        return None
    return [int(p.strip()) for p in v.split(",") if p.strip()]


class Config:
    def __init__(self) -> None:
        interfaces_env = os.environ.get("LEON_INTERFACES", "")
        self.interfaces: list[str] = [i.strip() for i in interfaces_env.split(",") if i.strip()]
        if not self.interfaces:
            self.interfaces = ["lo", "wlan0"]

        self.include_icmp: bool = _env_bool("LEON_INCLUDE_ICMP", False)
        self.port_allowlist: list[int] | None = _env_ports("LEON_PORTS")
        self.drop_link_local: bool = _env_bool("LEON_DROP_LINK_LOCAL", True)
        self.flow_idle_timeout: float = float(os.environ.get("LEON_FLOW_IDLE", "60"))
        self.flow_active_timeout: float = float(os.environ.get("LEON_FLOW_ACTIVE", "300"))
        self.block_honeypot_enabled: bool = _env_bool("LEON_HONEYPOT_ENABLED", True)
        self.honeypot_dwell_secs: float = float(os.environ.get("LEON_HONEYPOT_DWELL", "30"))
        self.honeypot_ports: list[int] = [
            int(p.strip()) for p in os.environ.get("LEON_HONEYPOT_PORTS", "2323").split(",") if p.strip()
        ]
        self.whitelist: list[str] = [
            ip.strip() for ip in os.environ.get("LEON_WHITELIST", "127.0.0.1").split(",") if ip.strip()
        ]

        # L6 decision engine
        self.alert_confidence: float = float(os.environ.get("LEON_ALERT_CONFIDENCE", "0.50"))
        self.block_confidence: float = float(os.environ.get("LEON_BLOCK_CONFIDENCE", "0.90"))

        # L7 IPS
        self.prevent_mode: bool = _env_bool("LEON_PREVENT", False)
        self.block_timeout: float = float(os.environ.get("LEON_BLOCK_TIMEOUT", "3600"))  # 0 = permanent
        self.blocks_file: str = os.environ.get("LEON_BLOCKS_FILE", "prevention/blocks.json")

        # Dashboard
        self.dashboard_host: str = os.environ.get("LEON_DASHBOARD_HOST", "127.0.0.1")
        self.dashboard_port: int = int(os.environ.get("LEON_DASHBOARD_PORT", "8050"))

    def load_json(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            log.warning("config file not found: %s", p)
            return
        data = json.loads(p.read_text())
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self) -> dict:
        return {
            "interfaces": self.interfaces,
            "include_icmp": self.include_icmp,
            "port_allowlist": self.port_allowlist,
            "drop_link_local": self.drop_link_local,
            "flow_idle_timeout": self.flow_idle_timeout,
            "flow_active_timeout": self.flow_active_timeout,
            "block_honeypot_enabled": self.block_honeypot_enabled,
            "honeypot_dwell_secs": self.honeypot_dwell_secs,
            "honeypot_ports": self.honeypot_ports,
            "whitelist": self.whitelist,
            "alert_confidence": self.alert_confidence,
            "block_confidence": self.block_confidence,
            "prevent_mode": self.prevent_mode,
            "block_timeout": self.block_timeout,
            "blocks_file": self.blocks_file,
            "dashboard_host": self.dashboard_host,
            "dashboard_port": self.dashboard_port,
        }


def load_config() -> Config:
    cfg = Config()
    cfg.load_json(os.environ.get("LEON_CONFIG", str(Path(__file__).resolve().parent / "leon.json")))
    return cfg
