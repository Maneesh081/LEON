# LEON — How the Prevention Layers Work (L6 + L7 + Dashboard)

Plain-English walkthrough of the decision engine, the nftables IPS, the
honeypot, and the web dashboard. Read this when you forget how a piece fits
together. Pairs with `docs/model_explained.md` (L4 + L5).

---

## 1. The chain so far

```
sensor (L1–L3)  →  model (L4)  →  explain (L5)  →  decision (L6)  →  block (L7)
      flows             verdict          reasons         Allow/Alert/Block   nftables
                                                          ↓
                                              logs/events.jsonl  →  dashboard
```

L4 asks "is this flow normal or an attack?". L5 says "which features made the
model say that?". L6 answers the next question:

> **"What should LEON do about it?"** — Allow, Alert, or Block.

L7 answers "how do we stop them?" (nftables) and "how do we catch someone who
isn't attacking *yet*?" (honeypot). The dashboard just displays the event log
live.

---

## 2. L6 — The Decision Engine (`prevention/decision.py`)

### Inputs
- The **verdict** from `FlowClassifier.predict()`: `label, confidence,
  benign_probability, anomaly_score, novelty, alert`.
- The **flow** (to know who the attacker is — the flow initiator `src_ip`).
- The **config policy** (`whitelist`, `alert_confidence`, `block_confidence`).

### Outputs
A `Decision(action, attacker_ip, reason, confidence, source)`, written to the
event store as `{"layer": "L6", "type": "decision", ...}`.

### The rule table (evaluated top to bottom)
| # | Condition | Action |
|---|-----------|--------|
| 1 | IP in `LEON_WHITELIST` | **ALLOW** (never block whitelisted hosts) |
| 2 | honeypot probe | **BLOCK** (deterministic, conf = 1.0) |
| 3 | `label == ANOMALY` and `conf >= block_confidence` (0.90) | **BLOCK** `flow.src_ip` |
| 4 | any other `alert` (ANOMALY ≥ 0.50, **or** novelty) | **ALERT** |
| 5 | everything else | **ALLOW** |

Key decisions we made:

- **Novelty never blocks.** A novelty alert means "unusual, not a proven
  attack". On a home network, QUIC/YouTube/odd ports trip the novelty net all
  the time — blocking on it would cut you off. Novelty → ALERT only.
- **Block the flow initiator.** For port scans, SYN floods and DDoS the
  attacker is the side that *started* the flow, so that's `flow.src_ip`.
- **Detect-only by default.** `--prevent` (or `LEON_PREVENT=1`) turns on real
  blocking. Until then every flow is still classified and decided, but nothing
  is dropped — safe for a real network.

---

## 3. L7a — The nftables Blocker (`prevention/blocker.py`)

Linux firewalls are managed with **nftables**. LEON uses two dedicated tables
(one for IPv4, one for IPv6) so it never touches your other rules:

```
table ip leon {
  set blocked { type ipv4_addr; flags timeout; }
  chain input { type filter hook input priority 0; policy accept;
                ip saddr @blocked drop; }
}
```

- `@blocked` is a **named set** — a list of IPs. Adding/removing one IP is a
  single set-element operation, no rule reload needed.
- `flags timeout` gives **auto-expiry**: a blocked IP cleans itself out after
  `block_timeout` (default 3600 s). 0 = permanent.
- `block(ip)` / `unblock(ip)` / `list_blocked()` talk to the kernel through
  the `nft` command. The whole process runs as root (`sudo`), matching the
  rest of LEON.
- Blocks are persisted to `prevention/blocks.json`; `restore()` re-applies any
  not-yet-expired ones on startup (nftables sets are lost on reboot).

---

## 4. L7b — The Honeypot (`prevention/honeypot.py`)

A honeypot is a **decoy**. LEON opens a port (default `2323`) that runs no
real service. Nobody legitimate ever connects there, so a connection is almost
certainly a scanner/probe — a **deterministic** attack signal.

On a connection, LEON:
1. logs + emits `{"layer": "L7", "type": "honeypot.probe", ip, port}`,
2. holds the socket open for `honeypot_dwell_secs` (30 s) to waste the
   attacker's time,
3. feeds a synthetic `ANOMALY` verdict (conf = 1.0) into the DecisionEngine →
   rule #2 → **BLOCK** the attacker (enforced in prevent mode).

This catches the *early* phase of an attack: port scans usually happen before
the real assault.

---

## 5. `prevention/run_ips.py` — the full pipeline

One command ties it together:

```bash
sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot
```

```
capture → flows → features → RandomForest verdict → SHAP reasons
        → DecisionEngine → [block via nftables if prevent mode]
```

Plus block management:
```bash
sudo .venv/bin/python -m prevention.run_ips --list-blocks
sudo .venv/bin/python -m prevention.run_ips --unblock 1.2.3.4
```

---

## 6. The Dashboard (`dashboard/`)

### How it stays live
The pipeline writes every event to `logs/events.jsonl` (JSON lines). The
dashboard runs a background thread that **tails that file** and broadcasts each
new line over a **WebSocket** to every open browser. No coupling: the pipeline
(sudo, terminal 1) and the dashboard (no sudo, terminal 2) are separate
processes that only share the file.

### Tabs
- **Live** — counters (flows / alerts / blocked / honeypot probes), an
  alert+block cumulative trend chart, and the verdict feed: time, protocol,
  src→dst, label, confidence, novelty, and the Allow/Alert/Block action.
- **Models** — the training `comparison_report.json` as a table (RF vs XGBoost
  vs IsolationForest: accuracy, macro/weighted F1, benign FAR, attack recall),
  bar charts of the metrics, the winner's per-class precision/recall/F1, and
  its operational rates.
- **Blocks & Logs** — the IPs currently blocked in nftables, honeypot probes,
  and the raw recent event stream.

### Reading a verdict row
| Column | Meaning |
|--------|---------|
| `label` | RandomForest's call (BENIGN / ANOMALY) |
| `conf` | how sure RF is |
| `novelty` | YES = IsolationForest flagged an unusual pattern (ALERT only) |
| `action` | the DecisionEngine's Allow / Alert / Block |
| `reason` | why — e.g. "known attack (confidence 0.99 >= 0.90)" |

---

## 7. Safety model

- **Detect by default** — nothing is blocked until you say so.
- **Novelty never blocks** — unusual ≠ attack.
- **Whitelist first** — listed hosts are never blocked, no matter what.
- **Isolated nftables tables** — LEON only ever manages `ip leon` / `ip6 leon`.
- **Auto-expiring blocks** — a misfire can't lock an IP out forever.
- **Honeypot = deterministic** — connection to a dead port is a scan, no ML
  guesswork involved.

---

## 8. The files

| File | Role |
|------|------|
| `prevention/decision.py` | L6 DecisionEngine |
| `prevention/blocker.py` | L7 nftables blocker |
| `prevention/honeypot.py` | L7 active honeypot |
| `prevention/run_ips.py` | end-to-end pipeline CLI |
| `prevention/test_*.py` | offline + live tests |
| `dashboard/server.py` | FastAPI + WebSocket server |
| `dashboard/static/` | HTML/CSS/JS UI |
| `core/events.py` | JSON-lines event store (`logs/events.jsonl`) |
| `core/config.py` | policy: thresholds, whitelist, honeypot, dashboard |
