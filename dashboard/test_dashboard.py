"""Offline tests for the dashboard (FastAPI app, no browser)."""
import json
import os
import threading
import time

os.environ.setdefault("LEON_DASHBOARD_PORT", "8077")

import httpx  # noqa: E402  (fastapi testclient pulls httpx)

from fastapi.testclient import TestClient  # noqa: E402

from dashboard.server import app  # noqa: E402


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def test_health():
    print("test: /api/health")
    with TestClient(app) as client:
        r = client.get("/api/health")
        chk(r.status_code == 200 and r.json() == {"ok": True}, "health OK")


def test_models_endpoint():
    print("test: /api/models returns the comparison report")
    with TestClient(app) as client:
        r = client.get("/api/models")
        chk(r.status_code == 200, "200")
        data = r.json()
        chk("results" in data, "report has results")
        chk({"RandomForest", "XGBoost", "IsolationForest"} <= set(data["results"]),
            f"three models present, got {list(data['results'])}")


def test_index_served():
    print("test: index.html is served")
    with TestClient(app) as client:
        r = client.get("/")
        chk(r.status_code == 200 and "LEON Dashboard" in r.text, "index.html served")


def test_websocket_snapshot():
    print("test: websocket sends a snapshot + broadcasts live events")
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws:
            msg = ws.receive_json()
            chk(msg["type"] == "snapshot", "snapshot received")
        # simulate an event appearing in the tail (broadcast path)
        from dashboard.server import _record
        got = threading.Event()
        results = []
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()  # snapshot
            _record({"layer": "L4", "type": "verdict", "label": "BENIGN"})
            msg = ws.receive_json()
            results.append(msg)
            got.set()
        chk(results and results[0]["type"] == "verdict", "live event broadcast over ws")


def test_dataset_endpoint():
    print("test: /api/dataset returns training summary + sample")
    with TestClient(app) as client:
        r = client.get("/api/dataset")
        chk(r.status_code == 200, "200")
        data = r.json()
        if "error" in data:
            chk(False, f"dataset unavailable: {data['error']}")
        chk(len(data["features"]) == 11, "11 feature names listed")
        chk(data["total_rows"] > 0, f"total rows = {data['total_rows']}")
        chk(data["labels"]["BENIGN"] > 0 and data["labels"]["ANOMALY"] > 0,
            f"both classes present: {data['labels']}")
        chk(data["files"], "file list present")
        chk(data["sample"], "sample rows present")
        chk(set(data["sample"][0].keys()) == set(data["features"] + ["Label"]),
            "sample rows have the 11 features + Label")


if __name__ == "__main__":
    test_health()
    test_models_endpoint()
    test_dataset_endpoint()
    test_index_served()
    test_websocket_snapshot()
    print("\nALL DASHBOARD TESTS PASSED")
