import json
import time
from pathlib import Path

from core.log import get_logger

log = get_logger(__name__)


class EventStore:
    def __init__(self, path: str = "logs/events.jsonl") -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self.path = p

    def emit(self, layer: str, event_type: str, **fields) -> dict:
        record = {"layer": layer, "type": event_type, "ts": time.time(), **fields}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
        return record

    def recent(self, limit: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
