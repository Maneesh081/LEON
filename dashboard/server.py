"""LEON dashboard - FastAPI + WebSocket live view.

Serves a clean single-page UI and pushes live events from logs/events.jsonl
to every open browser over WebSocket. No root needed.

usage:
  .venv/bin/python -m dashboard.server            # then open http://127.0.0.1:8050
  ./run_dashboard.sh
"""
from __future__ import annotations

import asyncio
import glob
import json
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from core.config import load_config
from core.events import EventStore
from sensor.feature_spec import CSV_COLUMN_MAP, FEATURE_NAMES

BASE = Path(__file__).resolve().parent

cfg = load_config()
store = EventStore()

_history: list[dict] = []
_clients: set[WebSocket] = set()
_lock = threading.Lock()
_stop_tail = threading.Event()
_loop_ref: asyncio.AbstractEventLoop | None = None
_tail_thread: threading.Thread | None = None


def _record(rec: dict) -> None:
    with _lock:
        _history.append(rec)
        if len(_history) > 2000:
            del _history[: len(_history) - 2000]
        clients = list(_clients)
        loop = _loop_ref
    if loop is None or not clients:
        return
    for ws in clients:
        asyncio.run_coroutine_threadsafe(_send(ws, rec), loop)


async def _send(ws: WebSocket, rec: dict) -> None:
    try:
        await ws.send_json(rec)
    except Exception:
        pass


def _tail() -> None:
    """Poll the event file and broadcast new lines to browsers."""
    path = store.path
    pos = path.stat().st_size if path.exists() else 0
    while not _stop_tail.is_set():
        try:
            if path.exists():
                size = path.stat().st_size
                if size < pos:
                    pos = 0  # file was truncated/rotated
                if size > pos:
                    with path.open("r", encoding="utf-8") as fh:
                        fh.seek(pos)
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                _record(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                        pos = fh.tell()
        except OSError:
            pass
        _stop_tail.wait(0.25)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _loop_ref, _tail_thread
    _loop_ref = asyncio.get_running_loop()
    _tail_thread = threading.Thread(target=_tail, daemon=True, name="events-tail")
    _tail_thread.start()
    yield
    _stop_tail.set()
    if _tail_thread is not None:
        _tail_thread.join(timeout=2.0)


app = FastAPI(title="LEON Dashboard", lifespan=lifespan)


@app.get("/api/health")
def api_health() -> dict:
    return {"ok": True}


@app.get("/api/models")
def api_models() -> dict:
    report = BASE.parent / "model" / "models" / "comparison_report.json"
    if not report.exists():
        return {"error": "no comparison_report.json yet - run ./train_compare.sh"}
    try:
        return json.loads(report.read_text())
    except json.JSONDecodeError:
        return {"error": "comparison_report.json is corrupt"}


DATA_DIR = BASE.parent / "model" / "data" / "cleaned"
_dataset_cache: dict = {}


def _load_dataset() -> dict:
    files = sorted(glob.glob(str(DATA_DIR / "*_cleaned.csv")))
    if not files:
        return {"error": f"no *_cleaned.csv files in {DATA_DIR}"}
    sig = [(p, Path(p).stat().st_mtime, Path(p).stat().st_size) for p in files]
    if _dataset_cache.get("sig") == sig:
        return _dataset_cache["payload"]

    reverse = {csv_name: feat for feat, csv_name in CSV_COLUMN_MAP.items()}
    usecols = list(reverse) + ["Label"]
    file_rows: list[dict] = []
    sample: list[dict] = []
    total = bn = an = 0
    for path in files:
        frame = pd.read_csv(path, usecols=usecols).rename(columns=reverse)
        labels = frame["Label"].astype(str).str.strip().str.upper()
        benign_n = int((labels == "BENIGN").sum())
        total += len(frame)
        bn += benign_n
        an += len(frame) - benign_n
        file_rows.append({"name": Path(path).name, "rows": len(frame)})
        benign = frame[labels == "BENIGN"].sample(min(4, benign_n), random_state=42)
        attack = frame[labels != "BENIGN"].sample(min(4, len(frame) - benign_n), random_state=42)
        part = pd.concat([benign, attack])
        part = part.where(pd.notnull(part), None)
        for rec in json.loads(part.to_json(orient="records")):
            rec["Label"] = "BENIGN" if str(rec.get("Label", "")).strip().upper() == "BENIGN" else "ANOMALY"
            sample.append(rec)

    payload = {
        "files": file_rows,
        "total_rows": total,
        "labels": {"BENIGN": bn, "ANOMALY": an},
        "features": list(FEATURE_NAMES),
        "sample": sample,
    }
    _dataset_cache.update(sig=sig, payload=payload)
    return payload


@app.get("/api/dataset")
def api_dataset() -> dict:
    try:
        return _load_dataset()
    except Exception as exc:  # pragma: no cover
        return {"error": f"failed to read dataset: {exc}"}


@app.get("/api/events")
def api_events(limit: int = 200) -> dict:
    with _lock:
        return {"events": list(_history[-limit:])}


@app.get("/api/blocks")
def api_blocks() -> dict:
    from prevention.blocker import NftablesBlocker
    return {"blocked": NftablesBlocker(cfg).list_blocked()}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    with _lock:
        _clients.add(ws)
    try:
        await ws.send_json({"type": "snapshot", "events": list(_history)})
    except Exception:
        pass
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        with _lock:
            _clients.discard(ws)


app.mount("/", StaticFiles(directory=str(BASE / "static"), html=True), name="static")


def main() -> int:
    import uvicorn
    print(f"LEON dashboard: http://{cfg.dashboard_host}:{cfg.dashboard_port}")
    uvicorn.run(app, host=cfg.dashboard_host, port=cfg.dashboard_port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
