# LEON — Q&A Learning Log

Every question asked during development + the explanation, kept so we can
revisit lessons and carry them into new chat sessions. **This file is updated
every time a question is asked.**

Legend: Q = question asked · A = what we learned.

---

## Running LEON & Linux basics

### Q1. Why was there "no traffic"? Should I open a browser to generate it?
- LEON's capture filters to TCP+UDP and drops noise (ARP/broadcast/multicast/
  link-local).
- Two interfaces matter:
  - `lo` (loopback) — traffic between *your machine and itself* (curl to
    localhost, browser to `127.0.0.1`). Quiet if nothing talks to localhost.
  - `wlan0` (WiFi) — your traffic *to the internet* (browser, apps, DNS).
- A browser on the internet shows up on `wlan0`, NOT `lo`.
- To see loopback traffic: open `http://127.0.0.1:8080/plan.md` while
  capturing on `lo`.

### Q2. How do I run these Python commands? (Windows user, new to Linux)
`python file.py` (Windows) → LEON uses a project-aware form:
```
sudo  .venv/bin/python  -m  L_1_Packet_Capture.run_l1  -i lo  -d 8  -v
```
- `sudo` = run as administrator (Windows "Run as admin").
- `.venv/bin/python` = LEON's own Python inside its virtualenv (system Python
  on Arch is protected).
- `-m L_1_Packet_Capture.run_l1` = "run this file": folder `L_1_Packet_Capture`
  + file `run_l1.py` (dot instead of slash, no `.py`).
- `-i lo` = interface, `-d 8` = duration seconds, `-v` = verbose.
- Shorthand helpers: `./run_l1.sh`, `./test_l2.sh`, etc. exist in the project
  root and pass arguments through.

### Q3. Will LEON run on Linux Mint (professor's machine)?
- Yes. LEON is pure Python; needs only Python 3.10+ (Mint 22 ships 3.12,
  ours is 3.14 — code uses nothing newer than 3.10 features).
- Setup: `sudo apt install python3-venv` (if needed) → `python3 -m venv .venv`
  → `.venv/bin/pip install -r requirements.txt` → run with `sudo` as usual.
- Gotchas: interface names differ (`enp2s0`, `wl...`, `eth0` — check with
  `ip -o link show`, pass with `-i`); on WiFi LEON sees only your own station's
  traffic; needs a real Linux env (not a restricted container) for raw sockets
  and nftables.

---

## Layer 1 — Packet Capture

### Q4. What does a parser do? Is L1 just "prove we can capture packets"?
- A parser peels the layered "envelopes" of a packet:
  Ethernet (box) → IP header (address label: src/dst IP + protocol) →
  TCP/UDP header (ports + flags) → payload (data).
- Output is a structured `Packet`: `ts, src_ip, dst_ip, protocol, src_port,
  dst_port, flags, size, ...`.
- L1 is more than a demo — it's the foundation. Nothing downstream (flows,
  features, ML) works without parsed packets. L1 = unpacking boxes, L2 =
  sorting into bins, L3 = measuring, L4 = judging, L5 = explaining, L6 =
  deciding, L7 = acting.

### Q5. Reading the verbose packet line (`TCP 5.9.243.187:443 -> 10.249.198.91:45822 [A] 0B`)
- `wlan0` = interface it was seen on.
- `TCP` = protocol. `5.9.243.187:443` = source IP + port, `->` = direction,
  `10.249.198.91:45822` = destination IP + port.
- IP addresses: public (on the internet, e.g. the web server) vs private
  (10.x/192.168.x — your LAN machine).
- Ports = "apartment number" at the IP's "street address" → which app.
  443 = HTTPS, 80 = HTTP, 22 = SSH, 53 = DNS.
- `[A]` = TCP flags. S=SYN (start), A=ACK (acknowledge), F=FIN (close),
  R=RST (abort).
- `0B` = payload size in bytes (0 = control packet with no data).
- `accepted 83` = the funnel summary: frames (raw seen) → parsed (decodable)
  → noise (thrown away) → filtered (your rules) → **accepted** (kept for
  flows). 83 packets survived and will become flows.

### Q6. What is ping? What is echo?
- Ping = a tool that asks another machine "are you there?" and measures the
  reply time (RTT in ms).
- Echo = the two ICMP messages ping uses: **Echo Request** (type 8) "hello?"
  and **Echo Reply** (type 0) "yes, here I am."
- The receiver echoes back your data so you verify both directions work.
- Try: `ping 1.1.1.1`.
- ICMP = a small control protocol (not for data, for network "talking"). LEON
  ignores ICMP by default (`--icmp` to enable) since attacks we care about live
  in TCP/UDP flows.

### Q7. What is a flow? Why build flows instead of classifying packets?
- A single connection = a *conversation* of many packets. A flow groups all of
  one conversation's packets into one bucket using the **5-tuple**:
  (src IP, dst IP, src port, dst port, protocol).
- A lone SYN packet looks innocent; a *flow* of "1 packet, 0 replies, same
  port, repeated 10,000×" is unmistakably an attack. Flow stats are what the
  model learns from.

---

## Layer 2 — Flow Builder

### Q8. What are fwd/bwd, start_ts, last_ts?
- **fwd (forward)** = direction the first packet came from (whoever initiated).
- **bwd (backward)** = the reply direction.
- `start_ts` = timestamp of the flow's first packet; `last_ts` = timestamp of
  its most recent packet. `duration = last_ts - start_ts`.
- Counters: `fwd_packets/bwd_packets`, `fwd_bytes/bwd_bytes`,
  `syn/ack/fin/rst_count` (flags counted across the whole flow).
- Flows end via **idle timeout** (60s of silence) or **active timeout** (300s
  cap), then are emitted to the next layer.
- Attacks look lopsided: a SYN flood is mostly-forward, almost-no-backward.

### Q9. What does "flow 6" mean? / Why duration 0s?
- `6` is the IANA protocol number: 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6. LEON now
  prints `TCP`/`UDP` instead.
- Duration `0.00s` is display rounding — on loopback the whole conversation
  (SYN → SYN+ACK → ACK → RST) finishes in <1 ms. It's not really zero.
- This matters for L3: `packets_per_second = packets ÷ duration` → divide-by-
  zero guard (epsilon 1e-6) keeps PPS finite.

### Q10. Why did my flows show `rst=2 fin=0`? (L2 live output)
- RST = the connection was aborted, not politely closed (FIN).
- Cause: the traffic generator read only 1024 bytes then closed the socket,
  but the server had sent ~5.7KB — TCP sends RST when a socket closes with
  unread data. LEON correctly recorded it.
- This is real-world behavior: **port scanners flood RSTs**, so rst counts are
  a genuine attack signal.

---

## Layer 3 — Feature Extraction

### Q11. What are all those numbers in the L3 output?
Each row = one flow's 11 features (order from `feature_spec.py`):
1. `flow_duration` (s) 2. `protocol` (6 TCP / 17 UDP) 3. `dst_port`
4. `total_fwd_packets` 5. `total_bwd_packets` 6. `total_fwd_bytes`
7. `total_bwd_bytes` 8. `packets_per_second` 9. `syn_count` 10. `ack_count`
11. `rst_count`.

### Q12. Why don't we use src_port as a feature?
- src_port IS used — in the 5-tuple flow *key* (for grouping). But it's a bad
  *predictive feature*:
  - Random by design (ephemeral ports 32768+), different every connection.
  - Attackers randomize it too → no signal for attack vs benign.
  - Training on it = memorizing random numbers = overfitting.
- dst_port, by contrast, identifies the *service* being hit → flood/scan
  patterns ("same port over and over" / "many ports from one host").
- Rule: features should be informative, stable, non-random.

### Q13. Why is PPS so high (12k–15k)? Is that normal?
- `PPS = total_packets ÷ flow_duration` — an *instantaneous per-flow* rate.
- Loopback has ~zero latency → the flow's time window is sub-millisecond →
  4 packets in 0.0003s ≈ 13,000 PPS.
- On real WiFi traffic the same 4 packets span 0.05–0.5s → ~20–100 PPS.
- So high per-flow PPS is "normal" for instant flows; what signals a flood is
  the *aggregate*: thousands of weird flows per second hitting one service.
- Normalization handles the scale; high PPS is itself a known attack trait.

### Q14. The wlan0 run — why was PPS high on one row but low on others?
(rows from a live run, unscrambled)
- Row 1: TCP, 815 packets each way over 12.3s → **132 PPS sustained**. It was
  a mid-conversation flow (`syn=0, ack=1630`) — LEON joined after the
  handshake; every data packet carries an ACK.
- Row 2: TCP, 2 packets in ~0.3 ms → **5936 PPS** — an instant burst (the
  loopback phenomenon, just once).
- Rows 3–6: UDP to port 53 = **DNS** and 443 = **QUIC/HTTP-3**, one query +
  one reply over real network latency → 16–42 PPS.
- Takeaway: PPS is a ratio; its "normal" value depends on the time window.

### Q15. How does normalization make 0s and 1s? What are SYN/ACK?
- **Min-Max normalization:** `normalized = (value − column_min) ÷ (column_max
  − column_min)`. Min → 0, max → 1, middle → fraction. Each column gets its
  own min/max from the data it was *fitted on*. Purpose: put all features
  (duration ~0.1, bytes ~142k, PPS ~5k) on an equal 0–1 footing so scale
  doesn't dominate importance.
- **Must fit the scaler on training data (L4) and reuse it on live flows** —
  otherwise ranges differ between training and live.
- **SYN** = "start a connection"; **ACK** = "I received / agree." Handshake:
  SYN → SYN+ACK → ACK. Normal flow: syn 1–2, ack ≈ every data packet, rst 0.
- **Attack meaning:** `syn=1 ack=0 bwd=0` repeated = SYN flood; `syn=1 rst=1`
  = port scan; UDP flows always have all-zero TCP flags (UDP has no flags) —
  itself informative.
- Example from live data (`ack_count` min=0 max=1630): 1630→1.000, 2→0.001,
  0→0.000.

---

## L4 Machine Learning — Q&A

### Q. Which model won and why does it matter for live use?
- **RandomForest** (acc 0.9916, macroF1 0.9899) beat XGBoost (0.9913/0.9896)
  narrowly and IsolationForest by a lot. Saved as the live artifact.
- RF is also the easiest to explain later in L5 (SHAP/TreeExplainer) and to
  serve — no scaler needed inside its pipeline, works directly on raw features.

### Q. Why is IsolationForest kept if it only scores acc 0.70?
- It's a **novelty detector trained on BENIGN-only data**, not a classifier.
  Its job is not to label attacks — it's the **safety net** for zero-day /
  never-seen traffic patterns. Live alert rule:
  `label==ANOMALY and confidence>=0.50` OR novelty flag. In the live test a
  synthetic SYN-flood vector that RF called BENIGN was still ALERTED because
  the novelty score tripped. Layers catch each other.

### Q. Why binary (BENIGN vs ANOMALY) instead of 15 classes?
- CICIDS2017 has 15 classes but most are tiny (Heartbleed 11 rows, Infiltration
  36). 4000-class model would be noisy. Teammate's `binary_label` was reused:
  everything not BENIGN = ANOMALY. Class-specific analysis can come later.

### Q. Why did XGBoost suddenly predict ALL-BENIGN in the comparison?
- Its sklearn `Pipeline` only contained the model (no preprocessor). Training
  used **standardized arrays**; evaluation fed the **raw** test DataFrame →
  feature scales were off by orders of magnitude → model gave up and predicted
  the majority class.
- Fix: `Pipeline([("preprocess", scaler), ("model", xgb)])` so predict() also
  standardizes. Lesson: **training transform and predict transform must be
  identical**; a Pipeline guarantees it.

### Q. Why 40,000 cap per class, and why 400 trees?
- 40,000/class matches the teammate's dataset (keeps our comparison fair) and
  stops the huge BENIGN class (1.96M) from dominating. Result: 451K training
  rows.
- 400 trees × `min_samples_leaf=2` + `balanced_subsample` → strong per-class
  weighting without heavy overfitting; runtime is ~1–2 minutes.

### Q. What does benignFAR 0.0092 / attackRec 0.9937 mean for live ops?
- benignFAR = fraction of normal traffic falsely alerted (0.9% — fine, and the
  alert threshold 0.50 can raise it). attackRec = fraction of attacks detected
  (99.4%). For an IDPS we bias toward recall (don't miss attacks) over
  precision; the operator can tune threshold in `model/run_model.py --live`.

### Q. During the wlan0 live test one flow ALERTED with label=BENIGN — why?
- The main model (RandomForest) was 99.6% sure it was BENIGN. But the
  IsolationForest novelty safety net scored it -0.1716, below its alert
  threshold **-0.16208** → `novelty=YES` → ALERT. The threshold is calibrated
  so ~1% of normal flows get flagged as "unusual" (its benign false-alert
  rate = 1.06%) — deliberate, tunable paranoia for catching zero-day traffic.
- Real home Wi-Fi (QUIC, YouTube, unusual ports) contains flows unlike the
  CICIDS2017 lab "normal browsing" baseline, so such flows trip the novelty
  net even though they're harmless.
- Lesson: an ALERT is not proof of attack — the supervised model and the
  novelty net use different logic. SHAP explains the supervised model, not
  the novelty detector.

### Q. How does SHAP explainability work, and what bugs did we hit?
- SHAP (`TreeExplainer`) tells us, per feature, how much that feature pushed
  the RandomForest toward ANOMALY (positive) or BENIGN (negative), in
  log-odds units. `model/explain.py` applies the same preprocess step, then
  reads the anomaly class's contributions.
- Bug 1: the saved RF's classes are `['ANOMALY','BENIGN']` (alphabetical) —
  anomaly SHAP array is index 0, not 1. Derive from `model.classes_`.
- Bug 2: shap gives each feature a `[class0, class1]` pair (shape (1,11,2));
  you must take the anomaly *column*, not the first feature's pair.
- Test with a real labeled row to confirm contributions are sane (a benign
  row should have negative drivers; an ANOMALY row positive ones).

### Q. What does every number in the live output mean?
A verdict row like `[ALERT] label=BENIGN conf=0.9903 novelty=YES score=-0.1705`:
- `label` — RandomForest's verdict (the class with the higher probability).
- `conf` — confidence = the winner's `predict_proba` probability (0.9903 =
  99.03% sure it's BENIGN). It only reflects the RandomForest's opinion.
- `score` — IsolationForest anomaly score (`decision_function`). Negative =
  unusual; the more negative, the weirder the flow looks vs normal traffic.
- `novelty=YES` — flag when `score < anomaly_threshold` (-0.16208 in our
  artifact). The threshold allows ~1% of normal flows to be flagged on purpose.
- `ALERT` — final decision = `(label==ANOMALY and conf>=0.5) OR novelty`.
- JSON verdict also carries `benign_probability` = the other class's
  probability (≈ 1 − conf) and `features` = the 11 values.
- SHAP `why:` line = per-feature log-odds pushes: positive → toward ANOMALY,
  negative → toward BENIGN; strength buckets weak/moderate/strong.

### Q. Why are SHAP reasons for novelty alerts so mild ("toward BENIGN")?
- Because SHAP explains the **RandomForest**, and the RF calmly said BENIGN.
  The alert came from the **IsolationForest** novelty net, which SHAP can't
  explain here. So the `why:` line shows the RF's calm reasoning — expected.
- We now print `note: novelty flag - unusual pattern, NOT a known attack` on
  BENIGN-labeled alerts so the output is honest about where the alert came
  from.

### Q. Why does `--live` stop saying "capture stopped" and print nothing on lo?
- Not an error: `capture stopped on interface <iface>` is the normal
  end-of-run log after the duration elapses. On `lo` there's no background
  traffic, so no flows complete → no verdicts. Generate traffic (e.g.
  `python3 -m http.server 8080 --bind 127.0.0.1` + `curl`) or test on the
  real interface: `sudo ./run_model.sh -i wlan0 -d 30`.

---

## L6/L7 Decision Engine, IPS & Dashboard — Q&A

### Q. What is a honeypot?
- A **decoy** — a fake service/port placed to attract attackers and catch them.
  Real-world analogy: a fake unlocked safe in a vault — no legitimate customer
  ever touches it, so anyone who does is a thief.
- On a machine: you open a **decoy port** (default `2323`) that runs no real
  service. Normal users never connect there, so *any* connection is almost
  certainly a scanner/probe → a **deterministic attack signal with zero ML
  false positives**.
- Types: **low-interaction** (just listens + logs — what LEON uses) vs
  **high-interaction** (fake full OS/apps). Port scans usually happen *before*
  an attack, so the honeypot gives early warning.
- LEON holds the socket open for `honeypot_dwell_secs` (30s) to waste the
  attacker's time, then feeds a synthetic ANOMALY verdict (conf 1.0) into the
  DecisionEngine → BLOCK.

### Q. What does the L6 DecisionEngine do?
- Inputs: the **verdict** (label/confidence/novelty/anomaly_score), the
  **flow** (for the attacker IP) and the **config policy**.
- Outputs an **Allow / Alert / Block** action + reason + source + attacker IP,
  written to `logs/events.jsonl` for the dashboard.
- Rules, in order: whitelisted host → ALLOW; honeypot probe → BLOCK; ANOMALY
  with conf ≥ `block_confidence` (0.90) → BLOCK the flow initiator; any other
  alert (ANOMALY ≥ 0.50, or novelty) → ALERT; else ALLOW.
- The decision is **always computed**; it is only *enforced* (nftables rule)
  when prevent mode is on.

### Q. Which IP gets blocked when a flow is ANOMALY?
- The **flow initiator** (`flow.src_ip`). In our attack scenarios (port scan,
  SYN flood, DDoS) the attacker is the side that started the flow. The
  DecisionEngine takes the attacker IP from the flow's forward side.

### Q. Can a novelty-only alert ever trigger a block?
- **No.** Novelty = "unusual, but not a known attack" (the lesson from L4/L5).
  Blocking on it would cut off harmless home WiFi traffic — QUIC, YouTube and
  odd ports already trip the novelty net. Novelty → ALERT only, by design.

### Q. Why nftables named sets instead of one rule per IP?
- A **named set** holds all blocked IPs as elements; you add/delete elements
  without touching the chain or re-reloading rules.
- `flags timeout` gives **auto-expiry** — blocks clean themselves up (default
  3600s), which matches "the attacker is usually gone anyway".
- Everything lives in LEON's own `ip leon` / `ip6 leon` tables, so we **never
  touch the user's other firewall rules**, and setup is idempotent.
- Blocks are persisted to `prevention/blocks.json` and re-applied on restart
  (nftables sets do not survive a reboot).

### Q. Why is LEON detect-only by default?
- Decisions are computed and logged, but **no block happens** until
  `--prevent` / `LEON_PREVENT=1`. Safer: if the model misfires on a real
  network, you can't lock yourself out. plan.md's "Stage 7 — Enable IPS" is
  deliberately a separate, explicit step.

### Q. Why FastAPI + WebSockets for the dashboard (not Streamlit)?
- You asked for something clean and not Streamlit. FastAPI is async Python
  with **built-in WebSocket** support and trivial REST endpoints. The frontend
  is vanilla HTML/CSS/JS + Chart.js from a CDN — no build step, one page, dark
  theme. New deps: only `fastapi` + `uvicorn[standard]`.

### Q. How does the dashboard get live data?
- The pipeline (`run_ips.py`) already writes every verdict, decision and
  honeypot probe to `logs/events.jsonl` via `core/events.EventStore`.
- The dashboard **tails that file** (a background thread polls it) and
  broadcasts each new line over WebSocket to every open browser. No coupling:
  the pipeline and dashboard are separate processes. Run the pipeline with
  `sudo` in terminal 1, the dashboard (no sudo) in terminal 2.

### Q. What exactly does the dashboard show?
- **Live tab** — counters (flows / alerts / blocked / probes), an alert+block
  trend chart, and a live verdict feed (time, protocol, src→dst, label, conf,
  novelty, action, reason).
- **Models tab** — `model/models/comparison_report.json` rendered as a table +
  bar charts (accuracy / macroF1 / weightedF1 per model), the winner's
  per-class precision/recall/F1, and operational rates (benign FAR, attack
  recall).
- **Blocks & Logs tab** — currently blocked IPs (from nftables), honeypot
  probes, and the raw recent event stream.

### Q. How do I run everything on Omarchy (Arch + Hyprland)? — I'm new to Linux
- Open a terminal with **Super+Return**, then `cd ~/Projects/LEON`.
- Offline tests (no root): `./test_sensor.sh`, `./test_model.sh`,
  `./test_prevention.sh`, `./test_dashboard.sh`.
- Live (needs root): `sudo ./run_ips.sh --live -i wlan0 -d 30` — `sudo` asks
  for your password, just type it.
- Full IPS: `sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot`.
- Dashboard (no root): `./run_dashboard.sh` → browser at
  `http://127.0.0.1:8050` (`Super+B` or `omarchy launch browser`).
- Tip: use **two terminals** — one for the sudo capture, one for the dashboard.

### Q. Will this run on Linux Mint (the professor's machine)?
- Yes. Mint 22 ships Python 3.12 (LEON needs 3.10+). Setup:
  `sudo apt install python3-venv python3-pip nftables` → `python3 -m venv .venv`
  → `.venv/bin/pip install -r requirements.txt`.
- Gotchas: interface names differ (`enp2s0`/`eth0`/`wl...` — check with
  `ip -o link show` and pass `-i`); on WiFi LEON sees only your own station's
  traffic; needs a **real Linux** environment (not a restricted container) for
  raw sockets and nftables. All the run commands are identical to Omarchy's.

### Q. Why didn't the SHAP explanation show up on the dashboard?
- Because it was only **printed to the terminal** by `run_ips.py` — never
  stored in the event stream the dashboard tails. Fixed: `run_ips.py` now
  computes `explainer.readable(...)` for **every alert automatically** (no
  `--explain` needed; `--explain` extends it to all flows), puts it in the
  verdict, and `decision.py` writes it into the L6 event → new **"why (SHAP)"**
  column in the Live feed (wrapping cell, full text on hover). No explanation
  field = "—".

### Q. Do nc / nmap need both machines on the same WiFi? Will it harm my hotspot?
- Yes, both ends must share the same L3 network. Your **phone hotspot counts**:
  the phone becomes the AP and the laptop a client on the same subnet, so they
  can reach each other.
- No, it won't harm the network. `nc <ip> 2323` is **one TCP SYN** to a dead
  port (that IS the honeypot signal). `nmap -sS <single-ip>` is a few dozen
  SYN packets to one host — negligible. Just never scan networks you don't own.
- One-machine alternative (no phone tools): self-probe with
  `nc <your-wlan0-ip> 2323` — the source IP is your wlan0 IP (not the
  whitelisted 127.0.0.1), so it routes through wlan0, gets captured, and
  honeypot → BLOCK works.

### Q. I only had the localhost dashboard open, so why was the live capture so quiet?
- The dashboard at `127.0.0.1:8050` is **loopback** — it rides the `lo`
  interface, NOT wlan0, so browsing it produced **zero** wlan0 packets.
- The 30s capture saw the machine's *real* WiFi traffic: DNS, ARP, background
  chatter — mostly BENIGN, hence the quiet feed. To make it interesting you
  need traffic that actually crosses wlan0 (browse/download on a phone, or run
  the honeypot/nmap self-tests above).

### Q. Can you explain the IPS layers from scratch? I'm new to this field.
- **L1 capture** — grabs raw packets off the WiFi adapter (raw socket, sudo).
- **L2 flows** — groups packets into conversations (5-tuple), tracks timeouts.
- **L3 features** — summarizes each flow into 11 numbers (duration, ports,
  packet/byte counts, SYN/ACK/RST flags, speed).
- **L4 model** — RandomForest + an IsolationForest novelty net. Decides
  BENIGN vs ANOMALY and how sure it is.
- **L5 explain** — SHAP: which features pushed toward ANOMALY and why.
- **L6 decision** — policy rules turn the verdict into Allow / Alert / Block
  (whitelist first; honeypot → block; ANOMALY ≥ 0.90 → block src_ip; novelty
  → alert only).
- **L7 block** — nftables auto-expiring rules drop the attacker's IP; the
  honeypot listens on a decoy port so connecting = deterministic scanner.
- A **flow** is a conversation; the **initiator** (`src_ip`) is who started it
  and who gets blocked. **Detect-only** = classify + decide but don't drop.

### Q. What are the steps to run LEON again from scratch?
```bash
cd ~/Projects/LEON
./test_sensor.sh && ./test_model.sh && ./test_prevention.sh && ./test_dashboard.sh   # offline, no root
sudo ./test_ips_live.sh                    # kernel proof: real nftables block/verify/unblock
sudo ./run_ips.sh --live -i wlan0 -d 60 --prevent --honeypot    # terminal 1, full IPS
./run_dashboard.sh                         # terminal 2 -> http://127.0.0.1:8050
# optional demo traffic on wlan0 (same machine):  nc <your-wlan0-ip> 2323
```

---

## Network concept cheat-sheet

- **IP** = machine address (public = internet, private 10./192.168. = LAN).
- **Port** = which app on the machine. **5-tuple** = identity of one
  conversation.
- **TCP flags**: S start, A acknowledge, F finish, R reset.
- **ICMP** = control protocol (ping). **UDP** = fire-and-forget, no handshake.
- **Flow** = one conversation's packets grouped + summarized.
- **fwd/bwd** = direction the conversation started vs the reply side.
- **duration** = last_ts − start_ts. **PPS** = packets ÷ duration.
- **Feature vs key**: src_port is a key (identity), dst_port is a feature
  (service being attacked).
- **Honeypot** = a fake service (open port, no real app) used to bait scanners;
  anyone connecting is almost certainly an attacker.
- **nftables set** = a named list of IPs; add/delete an element without
  touching the rules. `flags timeout` makes entries auto-expire.
- **Whitelist** = hosts LEON never blocks, no matter what the model says.
- **Rule-based detection** = hard-coded logic (e.g. "100+ SYNs with 0
  responses = SYN flood") that runs alongside the ML model. Real firewalls
  always have both: rules catch obvious attacks instantly, ML catches novel
  ones.
- **Blocking own IP** = `ip saddr @blocked drop` in the INPUT chain only
  drops *incoming* packets FROM the blocked IP. Your outgoing traffic still
  leaves via wlan0 with src=your-IP, but the gateway (10.200.130.1) responds
  from a *different* IP — so internet still works. Same-machine traffic on
  loopback IS affected (the kernel sees it as incoming from yourself).

---

## Decision engine & SYN flood blocking

### Q: Why did the DDoS not get blocked even though LEON saw all 1000 SYNs?
- The **ML model (RF)** classified the same-IP loopback flood as BENIGN
  (conf=0.5267) — it was trained on CICIDS-2017 where attacks come from
  *different* IPs. Same-IP-to-same-IP traffic is out-of-distribution.
- The **IsolationForest** correctly flagged novelty (score < threshold), but
  novelty never blocks by design (too many false positives on home networks).
- **Fix:** Added a rule-based SYN flood detector to the DecisionEngine:
  `syn_count >= 100 AND bwd_packets == 0 → BLOCK`. This fires before the
  ML model and catches SYN floods regardless of what the model says.

### Q: Does the SYN flood rule go into the NGFW?
- Yes. The DecisionEngine *is* the L6 "brain" of the NGFW. The rule sits
  alongside the ML model, just like the honeypot rule. Rule-based checks for
  obvious attacks + ML for novel ones = standard NGFW architecture.

### Q: How do I see which IPs are blocked?
```bash
nft list set ip leon blocked
```
Or via LEON: `sudo .venv/bin/python -m prevention.run_ips --list-blocks`

### Q: Will a separate attacker laptop trigger BLOCK?
- Most likely yes. With different IPs, the traffic matches CICIDS-2017 DoS
  patterns the RF was trained on. The model is more likely to classify as
  ANOMALY with high confidence. Plus the SYN flood rule catches it regardless.

### Q: Why doesn't the ML model detect SYN floods on its own?
- CICIDS-2017 has **zero SYN flood samples**. Its "DDoS" category is UDP/ICMP
  floods (no TCP flags). "DoS Hulk" is HTTP GET floods. Neither produces SYN
  flags. The model has never learned what a SYN flood looks like.
- Specifically: across all 2.37M training rows, `syn_count > 0 AND
  rst_count > 0` appears in **zero rows**. The model sees a flow with
  `syn=2000, rst=2000, bwd=2000` and classifies it as BENIGN because that
  feature combination was never labeled as attack in training.
- **The model isn't broken — the training data has a blind spot.** This is why
  the rule-based SYN flood detector is essential. Production firewalls always
  have both: rules for obvious attacks, ML for novel ones.

### Q: Should we retrain with more anomaly data?
- Yes, for the project's completeness. Adding synthetic SYN flood flows
  (both open-port and closed-port variants) to the training CSVs would let
  the model learn the pattern. But the rule-based fix works immediately and
  is sufficient for the demo. Retraining is a longer-term improvement.

---
*Last updated: Rule-based SYN flood detection added and verified on loopback. 49 tests pass. Docs updated for Linux Mint compatibility.*
