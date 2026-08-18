# LEON — Learning and Explaining Offensive-Network Patterns

A **real-time Explainable AI Intrusion Detection and Prevention System
(XAI-IDPS)**. LEON captures live network traffic, groups packets into flows,
extracts ML features, detects attacks with a trained RandomForest model,
explains every prediction with SHAP, makes an **Allow / Alert / Block**
decision, lures attackers into a **honeypot**, and blocks them via
**nftables** — all shown live on a clean web dashboard.

```
Traffic → Packet Capture → Flow Builder → Feature Extraction
        → RandomForest (+IsolationForest novelty net) → SHAP explanation
        → Decision Engine → Allow / Alert / Block
        → nftables (block) + Honeypot + Dashboard
```

## Quick start from GitHub

```bash
# clone the repo
git clone https://github.com/Maneesh081/LEON.git
cd LEON

# create venv + install pinned deps (Mint/Ubuntu — use python3; Arch — python)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# fetch the CICIDS-2017 training data (113 MB, for the Dataset tab + optional retrain)
./fetch_data.sh

# offline tests (no root needed)
./test_sensor.sh && ./test_model.sh && ./test_prevention.sh && ./test_dashboard.sh

# live IPS demo (two terminals)
sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot   # terminal 1
./run_dashboard.sh                                              # terminal 2 → http://127.0.0.1:8050
# test honeypot probe from same machine:  nc <your-wlan0-ip> 2323
```

> The trained model (`best_model.joblib`, ~48 MB) is committed to the repo, so
> no retraining is needed — live detection is inference only.  Data is fetched
> separately via `fetch_data.sh` from
> [A26D/LEON](https://github.com/A26D/LEON) (see `fetch_data.sh`).

## Repository layout

| Path | What it is |
|------|-----------|
| `core/` | shared config, logging, JSON-lines event store |
| `sensor/` | L1 packet capture, L2 flow builder, L3 feature extraction |
| `model/` | L4 training (RF vs XGBoost vs IsolationForest) + live classifier |
| `model/explain.py` | L5 SHAP explainer |
| `model/models/best_model.joblib` | trained RandomForest + IsolationForest artifact |
| `prevention/` | L6 decision engine, L7 nftables blocker + honeypot |
| `dashboard/` | FastAPI + WebSocket live web UI |
| `docs/` | explanatory write-ups (model walkthrough, IPS walkthrough, build log, Q&A) |

## Prerequisites

- **Linux** (Arch/Omarchy or Ubuntu/Linux Mint) — needs real root for raw
  sockets and nftables. A container or VM without raw-socket access won't work.
- **Python 3.12** recommended (LEON targets 3.10+; pinned deps have wheels
  for 3.12).
- **nftables** installed.
- Root (`sudo`) for live capture and blocking.
- A real network interface (Wi-Fi sees only your own station's traffic).

## Setup

### Arch / Omarchy

```bash
sudo pacman -S python nftables git
git clone https://github.com/Maneesh081/LEON.git ~/Projects/LEON
cd ~/Projects/LEON
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Linux Mint / Ubuntu

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nftables git
git clone https://github.com/Maneesh081/LEON.git ~/Projects/LEON
cd ~/Projects/LEON
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

> **Linux Mint gotchas**: your interface names differ from `wlan0` — find them
> with `ip -o link show` and pass `-i <name>`. Mint ships Python 3.12 (fine —
> LEON targets 3.10+). You need a real Linux install, not a restricted
> container, for raw sockets and nftables.

## Run it

All commands run from the project root. Tests first:

```bash
./test_sensor.sh        # offline L1+L2+L3 tests (no root)
./test_model.sh         # offline model + SHAP tests (no root)
./test_prevention.sh    # offline decision/blocker/honeypot tests (no root)
./test_dashboard.sh     # offline dashboard tests (no root)
sudo ./test_ips_live.sh # real nftables block/verify/unblock (root)
```

### Live detection + decisions (detect-only by default)

```bash
sudo ./run_ips.sh --live -i wlan0 -d 30            # classify + decide every flow
sudo ./run_ips.sh --live -i wlan0 -d 30 --explain  # + SHAP reasons on all flows
```

`wlan0` is an example — use your real interface (check `ip -o link show`).
SHAP reasons appear in the Live feed for **every alert automatically** (no flag
needed); add `--explain` to see them for all flows.

### Full IPS: auto-block + honeypot

```bash
sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot
```

- `--prevent` creates real nftables drop rules for attacker IPs (auto-expire
  after `block_timeout`, default 3600 s).
- `--honeypot` opens decoy ports (default `2323`); anyone who connects is a
  scanner → immediately blocked in prevent mode.
- Without `--prevent`, decisions are still logged but **nothing is blocked**
  (safe default for real networks).

Block management:

```bash
sudo .venv/bin/python -m prevention.run_ips --list-blocks
sudo .venv/bin/python -m prevention.run_ips --unblock 1.2.3.4
```

### Dashboard (no root — run in a second terminal)

```bash
./run_dashboard.sh          # then open http://127.0.0.1:8050 in a browser
```

The dashboard shows the trained model comparison, live verdicts as flows are
classified, SHAP explanations in the verdict feed, honeypot probes, blocked
IPs, and the raw event log — streamed live over WebSocket from
`logs/events.jsonl`.

## Training the model (optional — already trained)

`fetch_data.sh` downloads 8 cleaned CICIDS2017 CSVs (~117 MB) from a teammate
repo; `train_compare.sh` trains RandomForest, XGBoost and IsolationForest and
saves the winner as the live artifact.  You do **not** need to retrain — the
pre-trained `best_model.joblib` is committed to the repo.

```bash
./fetch_data.sh
./train_compare.sh                    # full run (minutes)
./train_compare.sh --quick            # fast smoke run
```

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `LEON_INTERFACES` | `lo,wlan0` | interfaces to capture on |
| `LEON_PORTS` | unset | optional port allowlist (`80,443,...`) |
| `LEON_INCLUDE_ICMP` | `0` | also capture ICMP |
| `LEON_WHITELIST` | `127.0.0.1` | hosts that are never blocked |
| `LEON_ALERT_CONFIDENCE` | `0.50` | ANOMALY confidence that triggers an alert |
| `LEON_BLOCK_CONFIDENCE` | `0.90` | ANOMALY confidence that triggers a block |
| `LEON_PREVENT` | `0` | master switch for actual blocking |
| `LEON_BLOCK_TIMEOUT` | `3600` | block auto-expiry in seconds (0 = permanent) |
| `LEON_HONEYPOT_ENABLED` | `1` | enable the honeypot |
| `LEON_HONEYPOT_PORTS` | `2323` | decoy ports |
| `LEON_HONEYPOT_DWELL` | `30` | seconds to hold a probe open |
| `LEON_DASHBOARD_PORT` | `8050` | dashboard HTTP port |

## Docs & learning log

All in the `docs/` folder:

- `docs/model_explained.md` — how the ML + SHAP layers work in plain English.
- `docs/ips_and_dashboard_explained.md` — L6 decision engine, L7 nftables + honeypot, dashboard walkthrough.
- `docs/plan.md` — original build plan per layer.
- `docs/PROGRESS.md` — build log per layer.
- `docs/q.md` — every Q&A from development (network concepts, Linux, LEON layers, dashboard design).
