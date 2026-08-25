# LEON — Progress Log

> **LEON (Learning and Explaining Offensive-Network Patterns)** is a Real-Time
> Explainable AI Intrusion Detection and Prevention System (XAI-IDPS). It
> captures live network traffic, groups packets into flows, extracts ML
> features, detects attacks with a trained model, explains every prediction
> with SHAP, makes Allow/Alert/Block decisions, lures attackers with
> honeypots, and blocks them via Linux nftables.

## Architecture (7 layers)

| Layer | Folder | Status |
|-------|--------|--------|
| L1 | `sensor/` | ✅ DONE |
| L2 | `sensor/` | ✅ DONE |
| L3 | `sensor/` | ✅ DONE |
| L4 | `model/` | ✅ DONE |
| L5 | `model/` (SHAP) | ✅ DONE |
| L6 | `prevention/` (decision engine) | ✅ DONE |
| L7 | `prevention/` (nftables + honeypot) | ✅ DONE |

Shared: `core/` (config, logging, event store) + `dashboard/` (FastAPI + WebSocket UI) ✅.

Docs: `docs/model_explained.md` walks through L4+L5 in plain English;
`docs/ips_and_dashboard_explained.md` walks through L6+L7+dashboard.

Docs: `docs/model_explained.md` walks through L4+L5 in plain English.

Environment: Python 3.14 venv at `.venv`, deps installed (numpy, pandas,
scikit-learn, xgboost, shap, joblib, scapy). Live capture and IPS need `sudo`.

---

## L1 — Packet Capture ✅

### What was built
- `core/config.py` — env-driven config (interfaces, `LEON_PORTS` allowlist,
  `LEON_INCLUDE_ICMP`, link-local drop, flow timeouts, honeypot settings).
- `core/log.py` — shared logger.
- `core/events.py` — JSON-lines event store (feeds the future dashboard).
- `L_1_Packet_Capture/packet.py` — Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP
  parsers. `Packet` dataclass carries the 5-tuple, TCP flags, sizes.
  `should_capture()` (protocol + port-allowlist filter), `is_noise()`
  (drops ARP/broadcast/multicast/link-local).
- `L_1_Packet_Capture/capture.py` — `CaptureSession`: `AF_PACKET` raw-socket
  capture thread + bounded queue; `packets()` streaming generator (yields a
  `None` heartbeat on idle so callers can honor deadlines); `sniff()` helper.
- `L_1_Packet_Capture/run_l1.py` — CLI: `-i`, `-d`, `-v`, `--icmp`.
- `L_1_Packet_Capture/test_l1.py` — offline parser/filter unit tests.
- `L_1_Packet_Capture/test_l1_live.py` — root live test (auto-generates
  loopback traffic, asserts packets captured + clean stop).

### Bug found & fixed during live test
`sniff()` used `for pkt in cap.packets()` on an endless generator → capture
never stopped and printed nothing. Fixed to pull via `next()` with an explicit
monotonic deadline, and `packets()` now yields `None` on idle as a heartbeat.

### Test results (verified)
- Unit tests: ALL PASS (SYN/ACK/data, UDP, ICMP, IPv6, VLAN, filtering, noise,
  malformed frames).
- Live test (sudo): **2444 TCP packets captured in 6.4s, clean stop,
  PASSED**.
- `run_l1 -i lo -d 8 -v` correctly reported 0 packets when no traffic was
  flowing (expected — no bug).

### How to run L1
```bash
sudo .venv/bin/python -m L_1_Packet_Capture.test_l1_live          # auto traffic, asserts
sudo .venv/bin/python -m L_1_Packet_Capture.run_l1 -i lo -d 8 -v  # live view
.venv/bin/python -m L_1_Packet_Capture.test_l1                    # offline tests
```
Capture restriction: TCP+UDP only by default (`--icmp`/`LEON_INCLUDE_ICMP`),
optional port allowlist via `LEON_PORTS=80,443,...`, noise (broadcast/
multicast/link-local/ARP) dropped automatically.

### Next step
**L2 — Flow Builder**: group packets into bidirectional flows keyed by
5-tuple; count fwd/bwd packets + bytes; expire idle flows (idle timeout 60s,
active timeout 300s) and emit completed flows.

---

## L2 — Flow Builder ✅

### What was built
- `L_2_Flow_Builder/flow.py` — `Flow` dataclass (5-tuple, start/last ts,
  fwd/bwd packets+bytes, syn/ack/fin/rst counts, duration) with `absorb()`.
  `FlowTable` with `update()` (routes reverse-direction packets to the same
  flow, first packet defines forward side), `expire(now)` (idle + active
  timeouts), `flush_all()`.
- `L_2_Flow_Builder/run_l2.py` — streams live packets -> FlowTable, emits each
  completed flow to the JSON event store + prints it. CLI: `-i -d -v --icmp
  --idle --active`.
- `L_2_Flow_Builder/test_l2.py` — offline tests (direction, flag counts,
  multi-flow separation, idle/active expiry, removal after expiry).
- `L_2_Flow_Builder/test_l2_live.py` — root live test: generates HTTP
  connections, asserts >=3 TCP flows each with fwd>=2 & bwd>=2.
- Helper scripts: `run_l1.sh`, `run_l2.sh`, `test_l1.sh`, `test_l2.sh`,
  `test_l1_live.sh`, `test_l2_live.sh` (all executable; `cd` into project
  root automatically, pass args through).

### Test results
- Offline unit tests: ALL PASS.
- Live test: pending user run (see below).

### How to run L2
```bash
./test_l2.sh                              # offline tests (no root)
sudo .venv/bin/python -m L_2_Flow_Builder.test_l2_live   # live auto-test
./run_l2.sh -i lo -d 10 -v                # live flow view
```
Flow example output:
`flow TCP 127.0.0.1:45822 -> 127.0.0.1:8080  fwd=12p/1450B bwd=10p/5230B syn=1 ack=21 fin=1 dur=1.2s`

### Next step
**L3 — Feature Extraction**: turn each completed flow into the 11-feature
vector + normalization scaler. `feature_spec.py` will be the single source of
truth shared with training (L4).

---

## L3 — Feature Extraction ✅

### What was built
- `L_3_Feature_Extraction/feature_spec.py` — THE single source of truth for
  the 11 features (shared with L4 training later):
  `flow_duration, protocol, dst_port, total_fwd_packets, total_bwd_packets,
  total_fwd_bytes, total_bwd_bytes, packets_per_second, syn_count, ack_count,
  rst_count`. Also `LABELS` for the model.
- `extractor.py` — `extract_features(flow)` computes PPS = total packets /
  duration with a `1e-6` epsilon guard (zero-duration flows like the
  sub-millisecond loopback ones never produce NaN/Inf).
- `normalizer.py` — `FeatureNormalizer`: sklearn `MinMaxScaler`, fit /
  transform / save / load (joblib). The scaler fitted on training data (L4)
  will be the one applied to live flows.
- `run_l3.py` — capture -> flows -> features -> normalize -> prints raw +
  normalized feature tables.
- `test_l3.py` (offline), `test_l3_live.py` (root auto-test).
- Scripts: `run_l3.sh`, `test_l3.sh`, `test_l3_live.sh`.
- Bonus: `flow.describe()` now prints `TCP`/`UDP` instead of protocol number 6/17.

### Test results
- Offline unit tests: ALL PASS (exact hand-computed feature values, zero-
  duration PPS guard, 11-feature spec order, MinMax fit/save/load roundtrip).
- Live auto-test on `lo`: **PASSED** (78 flows, all features finite).
- Live run on `wlan0`: **PASSED visually** — captured 13 flows incl. DNS (UDP
  53), QUIC (UDP 443), a sustained TCP flow (12.3s, 132 PPS) and an instant
  burst (2 packets / 0.3ms → 5936 PPS). PPS correctly reflected the time
  window (loopback ~13k vs real network 16–132).
- Confirmed the demo normalizer is fitted per-run (caveat: production scaler
  comes from L4 training data).

### How to run L3
```bash
./test_l3.sh   # offline (no root)
sudo ./test_l3_live.sh           # live auto-test
sudo ./run_l3.sh -i lo -d 10 -v  # live feature view
```

### Next step
**L4 — Machine Learning**: download CICIDS2017, preprocess it down to the same
11 features, train Random Forest + XGBoost, report metrics (accuracy/precision/
recall/F1 + confusion matrix), save model + scaler for the live path.

---

## L4 — Machine Learning ✅

### What was built
- `model/train_compare.py` — trains RandomForest, XGBoost and IsolationForest
  on the same 70/15/15 stratified split, prints a comparison table and saves
  the winner to `model/models/best_model.joblib` plus a
  `comparison_report.json`.
- `model/model.py` — `FlowClassifier`: loads the artifact, maps a live L3 flow
  dict → the 11 features, classifies, and emits a verdict
  `{label, confidence, anomaly_score, alert}`. Alert rule:
  `label==ANOMALY and confidence>=0.50` **OR** IsolationForest novelty flag.
- `model/run_model.py` — CLI: `--features`, `--jsonl`, `--live` (sensor
  capture → classify completed flows).
- `model/test_model.py` — offline tests (feature contract, verdict structure,
  alert rule, JSON serialization) — ALL PASS.
- Scripts: `run_model.sh`, `test_model.sh`, `train_compare.sh`, `fetch_data.sh`.

### Data source
- Used teammate's 8 cleaned CICIDS2017 CSVs (fetched by `fetch_data.sh` into
  `model/data/cleaned/`), NOT the full dataset. Verified they already match our
  exact 11-feature order, with `flow_duration` in **seconds** (no µs→s
  conversion needed) and `packets_per_second` precomputed.
- 2,375,892 rows total; binary target (BENIGN vs ANOMALY) — everything that is
  not BENIGN is an attack. Per-class training cap 40,000 (matches teammate).

### Training results (best of RF vs XGBoost vs IsolationForest)
Full run: 451,477 training rows, 316,033/67,722/67,722 split.

| model | kind | acc | macroF1 | wtF1 | benignFAR | attackRec |
|-------|------|-----|---------|------|-----------|-----------|
| RandomForest | supervised | 0.9916 | 0.9899 | 0.9916 | 0.0092 | 0.9937 |
| XGBoost | supervised | 0.9913 | 0.9896 | 0.9914 | 0.0106 | 0.9959 |
| IsolationForest | novelty | 0.7014 | 0.4128 | 0.5847 | 0.0106 | 0.0006 |

Winner: **RandomForest** (macroF1 0.9899) → saved as the live artifact.
IsolationForest is kept inside the artifact as a novelty backup (catches
zero-day/unknown patterns the supervised model was never trained on).

### Bug fixed during L4
XGBoost initially predicted ALL-BENIGN in the comparison run. Cause: its
pipeline had no preprocess step, so evaluation fed raw (unstandardized)
features while the model was trained on standardized arrays. Fix: wrap XGBoost
in a full `Pipeline([("preprocess", xgb_pre), ("model", xgb_model)])` and map
integer labels back to BENIGN/ANOMALY. After the fix XGB matched RF
(0.9859 → 0.9913 acc).

### How to run L4
```bash
./test_model.sh                              # offline tests (no root)
./train_compare.sh                           # full re-train (minutes)
sudo ./run_model.sh --live -i lo -d 15 -v    # live classification
```

### Next step
**L5 — SHAP Explainability**: explain every live prediction with SHAP and emit
an explanation (feature contributions) alongside the verdict. SHAP is already
installed in `.venv`.

---

## L5 — SHAP Explainability ✅

### What was built
- `model/explain.py` — `FlowExplainer`: wraps `shap.TreeExplainer` over the
  saved RF pipeline. `contributions(features)` returns one log-odds SHAP value
  per feature (positive = pushes toward ANOMALY); `top()` renders the top
  movers in each direction.
- `model/run_model.py`:
  - **Alerts now print the flow summary** (`flow.describe()` → 5-tuple,
    fwd/bwd packets+bytes, flags, duration) so you can see *what* triggered
    the alert.
  - `--explain` adds SHAP reasons to every flow; in live mode alerts are
    always explained.
  - **Plain-words reasons**: SHAP numbers are translated to
    `reply packets=44 → NORMAL (moderate) · dest port=443 → NORMAL (moderate)`
    (strength = weak/moderate/strong from |SHAP|).
  - **Novelty annotation**: a BENIGN-labeled alert that fired via the
    novelty net prints `note: novelty flag - unusual pattern, NOT a known
    attack`, so you never mistake it for a confirmed attack.
- `model/test_model.py` extended: SHAP contributions (11 values, finite,
  readable), plus a test against the real saved artifact. ALL PASS.
- `docs/model_explained.md` gained a "Reading the live output — every number
  explained" table (label/conf/score/novelty/benign_probability/SHAP).

### Bugs found & fixed
1. The saved RF's classes are `['ANOMALY', 'BENIGN']` (alphabetical), so the
   anomaly SHAP array is at index 0 — the explainer originally hardcoded 1
   and read the BENIGN class's values. Now derived from `model.classes_`.
2. shap returns each feature as a `[class0, class1]` pair (shape `(1, 11, 2)`);
   the code took only the first feature's pair instead of the anomaly column.
   Fixed with `row[:, anomaly_index]`.

### Example explanation (real ANOMALY row)
```
verdict: ANOMALY conf 1.0
key drivers: total_bwd_bytes=+0.286, dst_port=+0.129, protocol=+0.055, total_fwd_bytes=+0.029
```

### How to run L5
```bash
./test_model.sh                                          # offline tests (incl. SHAP)
sudo ./run_model.sh -i wlan0 -d 30 --explain             # live verdicts + reasons
.venv/bin/python -m model.explain --features '{...}'     # explain one flow
```

### Next step
**L6 — Decision Engine** (`prevention/`): turn a verdict (+explanation) into
an action — Allow / Alert / Block — using the config policy (whitelist, threat
confidence), then hand Block decisions to the nftables IPS (L7).

---

## L6 — Decision Engine ✅

### What was built
- `prevention/decision.py` — `DecisionEngine`: turns a live verdict + flow into
  a `Decision(action, attacker_ip, reason, confidence, source)`. Rules in
  order: whitelisted host → ALLOW (never block); honeypot probe → BLOCK
  (conf=1.0, deterministic); **SYN flood rule** → BLOCK (syn_count >= 100
  AND (bwd_packets == 0 OR rst_count == bwd_packets), conf=1.0, source="rule");
  `label==ANOMALY and conf >= block_confidence` → BLOCK the flow initiator
  (`flow.src_ip`); any other alert (ANOMALY ≥ 0.50 or novelty) → ALERT
  (**novelty never blocks**); else ALLOW.
- Every decision is written to the event store (`layer="L6", type="decision"`,
  incl. label/novelty/flow) and logged. Decisions are *computed* always,
  *enforced* only in prevent mode.
- `core/config.py` gained `alert_confidence` (0.50), `block_confidence` (0.90),
  `prevent_mode` (`LEON_PREVENT`), `block_timeout` (3600s), `honeypot_ports`,
  `blocks_file`, `dashboard_host/port`.
- `core/events.py` now stamps every event with `ts`.

### Test results
`prevention/test_decision.py` — ALL PASS (whitelist, high-conf block targeting
src_ip, below-threshold alert, novelty-never-blocks, honeypot deterministic
block, **SYN flood block (no responses)**, **SYN flood block (all-RST responses)**,
**SYN flood not triggered with ACK responses**, **SYN flood below threshold**,
normal allow, event logging, JSON round-trip).

### How to run L6
```bash
./test_prevention.sh                       # offline tests
sudo ./run_ips.sh --live -i wlan0 -d 30    # detect-only: decisions logged
```

### Next step
**L7 — nftables blocker + honeypot** (`prevention/`).

---

## L7 — nftables IPS + Honeypot ✅

### What was built
- `prevention/blocker.py` — `NftablesBlocker`: dedicated `ip leon` + `ip6 leon`
  tables, timeout-enabled named sets (`blocked`/`blocked6`) and an `input`
  chain dropping `saddr @blocked`. API: `ensure()` (idempotent), `block(ip,
  timeout)`, `unblock(ip)`, `list_blocked()`, `restore()` (re-applies
  `prevention/blocks.json` on start), `teardown()`. Isolated from the user's
  other nftables rules.
- `prevention/honeypot.py` — active TCP listener on `honeypot_ports` (default
  `2323`). Any connection = probe: emit `honeypot.probe` event, hold the socket
  open for `honeypot_dwell_secs`, then feed a synthetic ANOMALY verdict
  (conf 1.0) into the DecisionEngine → BLOCK.
- `prevention/run_ips.py` — CLI: `--live -i -d --explain --prevent --honeypot`,
  `--list-blocks`, `--unblock IP`. Full chain capture→flows→features→classify
  →explain→decide→(block).

### Test results
- `test_blocker.py` (mocked subprocess): ALL PASS (family detection, ensure
  commands v4+v6, block/unblock elements, set-output parsing, persistence +
  restore, teardown).
- `test_honeypot.py`: ALL PASS (probe fires callback with peer IP + event,
  clean stop).
- `test_ips_live.py` (root): **pending user run** — verify with
  `sudo ./test_ips_live.sh`.

### How to run L7
```bash
sudo ./test_ips_live.sh                                # live nftables test
sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot
sudo .venv/bin/python -m prevention.run_ips --list-blocks
```

### Next step
**Dashboard** (`dashboard/`): FastAPI + WebSocket live UI.

---

## Dashboard ✅

### What was built
- `dashboard/server.py` — FastAPI app: REST (`/api/health`, `/api/models`,
  `/api/events`, `/api/blocks`) + `/ws` WebSocket. A background thread tails
  `logs/events.jsonl` and broadcasts each new event to every open browser.
- `dashboard/static/index.html` + `style.css` + `app.js` — clean dark, tabbed
  single-page UI with Chart.js (CDN): **Live** (counters, alert/block trend,
  verdict feed), **Models** (comparison table + charts from
  `comparison_report.json`, winner badge), **Blocks & Logs** (blocked IPs,
  honeypot probes, raw event log).
- `run_dashboard.sh`, `test_dashboard.sh`. New deps: `fastapi`,
  `uvicorn[standard]` (added to `requirements.txt`).
- `README.md` — setup + run guide for Arch/Omarchy **and Linux Mint**.

### Test results
`dashboard/test_dashboard.py` — ALL PASS (health, models endpoint, index
served, WebSocket snapshot + live broadcast). Real server boot verified with
curl (index 200, /api/models JSON, /api/blocks).

### UI polish + Dataset tab + SHAP in the live feed (Aug 16)
- **Live tab** has a styled **cumulative** ALERT/BLOCK/ALLOW line chart
  with dark tooltips, integer axes, and fixed 250px height
  Shared dark-theme tooltips, integer axes, fixed 250px chart bodies
  (`app.js` `renderTrend`/`renderHistogram`, `style.css` `.chart-body`).
- **New `Dataset` tab** — shows what LEON trains on: the 8 CICIDS-2017 files
  in `model/data/cleaned/` (~2.4M rows), per-file row counts, BENIGN/ANOMALY
  class split (1,959,818 / 416,074), a class-distribution bar, and a
  **stratified sample** of 60 rows (4 benign + 4 attack per file) across the
  11 features. Backed by `GET /api/dataset` in `server.py`; the full read is
  cached and recomputed only when file mtimes change. Column-name mapping
  moved to a single source: `sensor/feature_spec.py` → `CSV_COLUMN_MAP`
  (shared with `model/train_compare.py`).
- **SHAP explanations now reach the dashboard.** Previously they were only
  printed to the terminal. `prevention/run_ips.py` computes
  `explainer.readable(...)` for **every alert automatically** (or every flow
  with `--explain`), stashes it in the verdict, and `prevention/decision.py`
  writes it into the L6 `decision` event → new **"why (SHAP)"** column in the
  Live feed table (wrapping cell, full text on hover). No `--explain` needed
  for alerts anymore.
- Tests: `dashboard/test_dashboard.py` gained an `/api/dataset` case;
  `prevention.test_decision` still green (explanation is optional/None-safe).

### How to run the dashboard
```bash
./test_dashboard.sh                 # offline tests
./run_dashboard.sh                  # terminal 2 (no sudo) -> http://127.0.0.1:8050
sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot   # terminal 1
```

### Dashboard block display fix (Aug 24)
- **Bug:** Block counter showed 0 even when blocks happened. Blocks & Logs tab
  showed "no IPs currently blocked" despite nftables having entries.
- **Root cause:** `loadBlocks()` polled `/api/blocks` every 5 seconds, which
  required root (nftables query). Dashboard runs without sudo → query silently
  failed → returned `[]` → overwrote the correct block counter to 0.
- **Fix:** Removed nftables polling entirely. Blocked IPs list now built from
  WebSocket events (`type === "decision" && action === "block"`). Block counter
  comes exclusively from `count("blocks")` in `render()`. No root needed,
  always in sync, real-time via WebSocket.

### Next step
**Final end-to-end testing** — run live attacks (SYN flood / port scan from a
test host), verify detection → SHAP → decision → block on the dashboard, and
confirm everything on Linux Mint. Docs: `docs/ips_and_dashboard_explained.md`.

---

## Testing & Bug Fixes (Aug 23–24)

### DDoS flood script — `scripts/ddos_flood.py`
- Created `scripts/ddos_flood.py` for same-machine DDoS testing using scapy
  with spoofed source IP. Rate-limited, auto-stops, progress output.
- **Error 1: MAC address warnings on wlan0.** `send()` at L3 tries to resolve
  destination MAC. When src == dst (same machine), scapy can't find the MAC
  for a local address → falls back to broadcast → WiFi drops packets → LEON
  never sees them.
- **Fix 1:** Detect same-machine via `_detect_same_machine()`, set
  `conf.iface = "lo"`. But `send(pkt, iface="lo")` is ignored by scapy at
  L3 — `iface` parameter has no effect on L3 `send()`.
- **Fix 2:** Use `sendp()` (layer 2) with `Loopback()` link-layer header for
  same-machine. scapy's `Loopback()` class creates the correct 4-byte
  loopback header. Separate machine uses normal `send()` on wlan0.
- Separate machine (no LEON clone needed): just `pip install scapy` on laptop B.

### Loopback capture — `sensor/packet.py`
- `CaptureSession` uses `AF_PACKET` raw sockets + `parse_packet()` which
  expected Ethernet frames (14-byte MAC header). Loopback frames have a
  4-byte address family header instead.
- **Error 2: All loopback frames failed parsing.** `parse_packet()` tried
  `_parse_eth()` on every frame → `PacketParseError("not an ethernet frame")`
  → zero packets accepted on lo.
- **Fix 1:** Added `_parse_loopback()` helper + auto-detection in
  `parse_packet()`: check first 4 bytes for loopback AF (2=IPv4, 10=IPv6)
  vs Ethernet. Works for both lo and wlan0 without flags.
- **Error 3: Loopback detection still failed.** scapy's `Loopback()` sends
  AF in **little-endian** (`02 00 00 00`), but code used big-endian
  (`struct.unpack("!I")` → read as 33554432, not 2). Frame fell through
  to Ethernet path → garbage parsing → dropped.
- **Fix 2:** Changed `struct.unpack("!I")` to `struct.unpack("<I")` (both in
  `_parse_loopback()` and `parse_packet()` detection). Two lines changed.
- **Verified:** Both loopback and Ethernet frames parse correctly. All 46
  tests pass. No impact on wlan0 (MAC bytes never produce 2 or 10 as LE).

### nmap testing — same machine
- Ran `nmap -sS -T4 --min-rate 100 -p 1-100 10.200.130.91` on lo.
- LEON captured on lo, classified each nmap probe individually (2-packet
  flows). Most classified BENIGN (conf 0.5–0.75), 2 triggered ALERT
  (ports 50, 73 → ANOMALY conf 0.51–0.52). None crossed block threshold
  (0.90) because each probe is too small (only 2 packets).
- nmap reported "100 filtered tcp ports" — kernel handles RST internally on
  loopback, nmap doesn't receive responses via raw socket.
- **Conclusion:** nmap works for detection (ALERT events fire) but not for
  blocking (per-probe confidence too low). DDoS script concentrates 500+ SYNs
  on one port → single flow with high signal → BLOCK.

### Honeypot probe testing — same machine
- Ran `nc 10.200.130.91 2323` from same machine.
- Source IP is wlan0 IP (10.200.130.91), NOT 127.0.0.1 → not whitelisted.
- DecisionEngine rule #2 fires: `source == "honeypot"` → BLOCK (conf=1.0).
- First probe detected and decided BLOCK. Subsequent nc attempts would be
  dropped by nftables.
- **Note:** `docs/testing.md` originally said "ALLOW: whitelisted host" for
  same-machine nc — this was wrong. Fixed to show correct BLOCK output.

### Testing docs — `docs/testing.md`
- Rewrote for same-machine workflow: no `-i wlan0` (captures on lo), DDoS
  script uses own IP, correct honeypot expected output, step 4 (gateway
  blocking) marked optional, all commands updated, troubleshooting table
  refreshed.

### Dashboard Models tab restyled
- Added color-coded pill badges (green=supervised, gold=novelty), winner row
  highlight, bold macro F1, rounded bar corners, per-model bar colors.
- Stale comment at `app.js:143` fixed (removed histogram reference).

### OneClassSVM — `model/train_compare.py`
- Added `SGDOneClassSVM` from sklearn (SGD-based, fast, trained on BENIGN
  only). Evaluated on same test split, added to `comparison_report.json`.
- Updated `docs/model_explained.md` in 6 places (intro, section 3d table,
  section 4, section 7 metrics, explanation, files table).

### GitHub
- Repo pushed: `https://github.com/Maneesh081/LEON.git` (public, `main`).
- Commit `7373096 model added` includes OneClassSVM + Models tab restyling.

### Errors encountered during this session

| # | Error | Where | Root cause | Fix |
|---|-------|-------|------------|-----|
| 1 | MAC address warnings on wlan0 | `ddos_flood.py` | scapy `send()` resolves dest MAC; local address has no MAC on wlan0 | Detect same-machine, use `sendp()` + `Loopback()` on lo |
| 2 | `send(pkt, iface="lo")` ignored | `ddos_flood.py` | scapy L3 `send()` ignores `iface` param | Use `sendp()` instead |
| 3 | All loopback frames → PacketParseError | `sensor/packet.py` | `parse_packet()` only handled Ethernet (14-byte MAC header) | Added `_parse_loopback()` + auto-detection |
| 4 | Loopback AF read as 33554432 | `sensor/packet.py` | Linux loopback uses little-endian; code used big-endian `!I` | Changed to `<I` (two lines) |
| 5 | nmap shows "filtered" on loopback | nmap itself | Kernel handles RST internally on lo; nmap raw socket doesn't see responses | Not a bug — nmap limitation on loopback |
| 6 | nmap probes not blocking | `decision.py` | Each probe is 2-packet flow → low RF confidence (0.51) < block threshold (0.90) | By design — use DDoS script for blocking demo |
| 7 | DDoS not blocking (RF said BENIGN) | `decision.py` | Same-IP loopback traffic is out-of-distribution for RF trained on CICIDS-2017; RF classifies as BENIGN conf=0.52 | Added rule-based SYN flood detector (syn>=100 AND bwd==0 → BLOCK). Real firewalls do this too. |
| 8 | Separate-laptop DDoS not blocking | `decision.py` | Target responds with RST (closed port) → bwd_packets=2000, old rule required bwd==0 | Extended rule: syn>=100 AND (bwd==0 OR rst==bwd) → catches closed-port SYN floods |

### SYN flood rule — successful BLOCK (Aug 24)
- Added rule-based SYN flood detection to `DecisionEngine`: `syn_count >= 100
  AND (bwd_packets == 0 OR rst_count == bwd_packets) → BLOCK` (conf=1.0,
  source="rule").
- This fires **before** the ML model — catches SYN floods regardless of what
  the ML says.
- **Covers two scenarios:** (a) no responses at all (open-port flood or
  same-machine), (b) all-RST responses (closed-port flood from separate laptop).
- **Same-machine verified:** `ddos_flood.py --src 10.200.130.91 --target
  10.200.130.91 --port 80 --count 500 --rate 100` → LEON showed:
  `[BLOCK] ... action: block - SYN flood (2000 SYNs, 0 responses, 0 RST)`.
- **Separate-laptop verified:** Target with closed port 80 → RST responses →
  `bwd=2000p rst=2000` → still BLOCKED by the `rst_count == bwd_packets`
  condition.
- Internet stays up after self-block because the nftables rule only drops
  incoming packets FROM the blocked IP — gateway responses come FROM a
  different IP.

---

## Learning log
All user Q&A and network concepts taught during development are kept in
`q.md` — updated after every question.
