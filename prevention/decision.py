"""L6 - NGFW decision engine: turn a verdict + flow into Allow/Alert/Block.

Rules, evaluated in order:

  1. whitelisted host            -> ALLOW   (never block whitelisted hosts)
  2. honeypot probe              -> BLOCK   (deterministic, confidence=1.0)
  3. ANOMALY and conf >= block   -> BLOCK   the flow initiator (flow.src_ip)
  4. any other alert (novelty)   -> ALERT   (novelty never blocks)
  5. else                        -> ALLOW

Decisions are always computed and written to the event store; they are only
*enforced* (nftables block) when prevent mode is enabled (see run_ips.py).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.config import Config
from core.events import EventStore
from core.log import get_logger

log = get_logger(__name__)

ALLOW = "allow"
ALERT = "alert"
BLOCK = "block"

# what triggered the decision
SRC_MODEL = "model"
SRC_NOVELTY = "novelty"
SRC_HONEYPOT = "honeypot"
SRC_WHITELIST = "whitelist"


@dataclass
class Decision:
    action: str
    attacker_ip: str
    reason: str
    confidence: float
    source: str

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "attacker_ip": self.attacker_ip,
            "reason": self.reason,
            "confidence": self.confidence,
            "source": self.source,
        }


class DecisionEngine:
    def __init__(self, config: Config | None = None, store: EventStore | None = None) -> None:
        self.config = config or Config()
        self.store = store or EventStore()

    def _record(self, decision: Decision, verdict: dict, flow: Any) -> Decision:
        fields = decision.to_dict()
        fields["label"] = verdict.get("label")
        fields["novelty"] = bool(verdict.get("novelty"))
        fields["explanation"] = verdict.get("explanation")
        if flow is not None:
            fields["flow"] = flow.to_dict()
        self.store.emit("L6", "decision", **fields)
        return decision

    def decide(
        self,
        verdict: dict,
        flow: Any = None,
        attacker_ip: str | None = None,
        source: str | None = None,
    ) -> Decision:
        ip = attacker_ip or (flow.src_ip if flow is not None else "")

        if self._whitelisted(ip):
            return self._record(Decision(
                ALLOW, ip, "whitelisted host - never blocked",
                float(verdict.get("confidence", 0.0)), SRC_WHITELIST), verdict, flow)

        if source == SRC_HONEYPOT:
            return self._record(Decision(
                BLOCK, ip, "honeypot probe - no real service should be contacted",
                1.0, SRC_HONEYPOT), verdict, flow)

        conf = float(verdict.get("confidence", 0.0))
        label = verdict.get("label")

        if label == "ANOMALY" and conf >= self.config.block_confidence:
            return self._record(Decision(
                BLOCK, ip,
                f"known attack (confidence {conf:.2f} >= {self.config.block_confidence:.2f})",
                conf, SRC_MODEL), verdict, flow)

        if verdict.get("alert"):
            if verdict.get("novelty"):
                return self._record(Decision(
                    ALERT, ip, "unusual pattern (novelty) - NOT a confirmed attack",
                    conf, SRC_NOVELTY), verdict, flow)
            return self._record(Decision(
                ALERT, ip,
                f"anomalous flow below block threshold (confidence {conf:.2f})",
                conf, SRC_MODEL), verdict, flow)

        return self._record(Decision(ALLOW, ip, "normal flow", conf, SRC_MODEL), verdict, flow)

    def _whitelisted(self, ip: str) -> bool:
        return ip in self.config.whitelist
