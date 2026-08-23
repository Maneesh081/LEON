# LEON — Full Demo & Testing Guide

Step-by-step guide to demonstrate every LEON feature on a single machine.
Works on the Omarchy laptop (or any Linux with Python 3.12+, nftables, scapy).

---

## Prerequisites

```bash
cd ~/Projects/LEON
source .venv/bin/activate          # or use .venv/bin/python directly
```

Make sure you know your wlan0 IP:
```bash
ip -o addr show wlan0 | awk '{print $4}' | cut -d/ -f1
# example output: 10.200.130.91
```

Replace `10.200.130.91` below with your actual wlan0 IP.

---

## Step 1: Start IPS + Dashboard

Open **3 terminals**.

**Terminal 1 — IPS (detect mode, no blocking yet):**
```bash
cd ~/Projects/LEON
sudo .venv/bin/python -m prevention.run_ips --live -d 300 --honeypot
```

Note: no `-i wlan0` — LEON captures on **all interfaces** (lo + wlan0) so it
sees same-machine DDoS traffic on loopback.

Wait until you see:
```
honeypot listening on port 2323
capture started on interface wlan0
```

And flows start scrolling:
```
[ALLOW] label=BENIGN   conf=1.0000  novelty=no  score=0.1352
      flow UDP 10.200.130.91:53354 -> 10.200.130.163:53 ...
      action: allow - normal flow
```

**What to say:** "This is LEON capturing live traffic on wlan0. Every flow is classified by the RandomForest model. Normal traffic gets ALLOW. Unusual patterns trigger novelty alerts."

**Terminal 2 — Dashboard:**
```bash
cd ~/Projects/LEON
./run_dashboard.sh
```

Open `http://127.0.0.1:8050` in a browser.

**What to say:** "The dashboard shows real-time verdicts. The cumulative chart tracks ALLOW/ALERT/BLOCK counts. The SHAP column explains why each verdict was made."

**Terminal 3 — Commands (for later steps):**
```bash
cd ~/Projects/LEON
```

---

## Step 2: Honeypot Trap (30 sec)

In **Terminal 3**, trigger the honeypot:
```bash
nc 10.200.130.91 2323
```

The `nc` command connects to port 2323 (a dead port with no real service).

**In Terminal 1 (IPS), you should see:**
```
[HONEYPOT] probe from 10.200.130.91 -> BLOCK: honeypot probe - no real service should be contacted
```

The honeypot detected the probe. The source is your wlan0 IP (not 127.0.0.1),
so it is NOT whitelisted and gets BLOCKED. In detect mode, no nftables rule is
created — just logged. In prevent mode, the IP would be immediately blocked.

**What to say:** "The honeypot is a decoy listener on port 2323. Nobody has a legitimate reason to connect here. The moment nc touches it, LEON detects a probe. In production with --prevent, the attacker's IP would be instantly blocked at the kernel level."

Press Ctrl+C in Terminal 3 to stop nc.

---

## Step 3: DDoS Detection (60 sec)

Now restart the IPS with **prevent mode** enabled. Ctrl+C Terminal 1, then:

**Terminal 1 — IPS (prevent mode):**
```bash
sudo .venv/bin/python -m prevention.run_ips --live -d 300 --prevent --honeypot
```

Wait until you see `prevent mode: nftables active` and flows scrolling.

**Terminal 3 — Run the DDoS attack (same machine):**
```bash
sudo .venv/bin/python3 scripts/ddos_flood.py --src 10.200.130.91 --target 10.200.130.91 --port 80 --count 500 --rate 100
```

Note: `--src` is your own IP. The script detects same-machine and sends on loopback.
LEON sees the flood on lo, classifies ANOMALY, blocks your IP. Internet stays up
because the nftables rule only drops incoming packets FROM your IP — responses from
the gateway come FROM `10.200.130.1`, not your IP.

You'll see:
```
SYN flood: 500 packets -> 10.200.130.91:80
  src=10.200.130.91  rate=100 pps  duration=~5s
  mode: same-machine (loopback)
  NOTE: run LEON without -i to capture on lo: sudo .venv/bin/python -m prevention.run_ips --live -d 300 --prevent --honeypot

  [  0.5s] sent 50/500 packets
  [  1.0s] sent 100/500 packets
  ...
  [  5.0s] sent 500/500 packets

Done. 500 packets sent in 5.0s
```

**In Terminal 1 (IPS), you should see:**
```
[BLOCK ] src=10.200.130.91  label=ANOMALY  conf=0.9987  reason=known attack (confidence 0.99 >= 0.90)
      flow TCP 10.200.130.91:xxxxx -> 10.200.130.91:80  fwd=500p/30000B bwd=0p/0B  syn=500 ack=0 ...
      action: block - known attack (confidence 0.99 >= 0.90)
      why: SYN flags=500 → ATTACK-like (strong) · speed=1000 → ATTACK-like (strong)
```

**What to say:** "The RandomForest model classified this as ANOMALY with 99.87% confidence. The SHAP explanation shows SYN flags and speed pushed hard toward ATTACK. The attacker IP is now blocked. My internet still works because the block only drops incoming packets FROM the attacker — my gateway is a different IP."

**Verify the block:**
```bash
nft list set ip leon blocked
# Output: { 10.200.130.91 }
```

**What to say:** "This is a real nftables rule at the kernel level. Any packet from 10.200.130.91 is dropped before it reaches the application. The block auto-expires after 3600 seconds. My internet still works — browse to any site to prove it."

**Unblock to restore full access:**
```bash
sudo nft delete element ip leon blocked { 10.200.130.91 }
```

**Check the dashboard:** The Live tab shows the attack flows with `action: block` and SHAP explanations.

---

## Step 4: Show Internet Dying (optional — skip if pressed for time)

After step 3, your IP is blocked but internet still works. To prove kernel-level
blocking actually kills connectivity, block the gateway manually:

```bash
sudo nft add element ip leon blocked { 10.200.130.1 }
```

**Try to browse the internet:**
- Open a browser, try any website → **fails**
- In Terminal 3, run: `ping 8.8.8.8` → **100% packet loss**

**What to say:** "I just blocked the gateway (my phone hotspot). All incoming internet traffic is now dropped by nftables. The internet is dead. This is what kernel-level blocking looks like. In production, LEON blocks the ATTACKER's IP, not the gateway — your internet stays up while the attacker is silenced."

**Unblock to recover:**
```bash
sudo nft delete element ip leon blocked { 10.200.130.1 }
```

---

## Step 5: SHAP Explainability (30 sec)

In Terminal 3, run SHAP on a sample attack flow:
```bash
.venv/bin/python -m model.explain --features '{
  "flow_duration": 0.001,
  "protocol": 6,
  "dst_port": 80,
  "total_fwd_packets": 500,
  "total_bwd_packets": 0,
  "total_fwd_bytes": 30000,
  "total_bwd_bytes": 0,
  "packets_per_second": 1000,
  "syn_count": 500,
  "ack_count": 0,
  "rst_count": 0
}'
```

**Output:**
```
SYN flags=500 → ATTACK-like (strong) · speed=1000 → ATTACK-like (strong) · duration=0.001 → ATTACK-like (moderate)
```

**What to say:** "SHAP explains the model's reasoning. For this SYN flood: 500 SYN flags strongly pushed toward ATTACK, 1000 packets/sec strongly pushed toward ATTACK. Every alert in the dashboard comes with this explanation."

Also run SHAP on a normal flow:
```bash
.venv/bin/python -m model.explain --features '{
  "flow_duration": 2.7,
  "protocol": 6,
  "dst_port": 443,
  "total_fwd_packets": 26,
  "total_bwd_packets": 47,
  "total_fwd_bytes": 3296,
  "total_bwd_bytes": 48322,
  "packets_per_second": 27,
  "syn_count": 2,
  "ack_count": 70,
  "rst_count": 2
}'
```

**Output:**
```
reply packets=47 → NORMAL (moderate) · dest port=443 → NORMAL (moderate) · bytes sent=3296 → NORMAL (moderate)
```

**What to say:** "For normal HTTPS traffic, the model sees balanced packets, port 443, and moderate byte counts — all pushing toward NORMAL."

---

## Step 6: Dashboard Walkthrough (30 sec)

Switch to the browser showing the dashboard.

**Live tab:**
- Cumulative chart: shows ALLOW/ALERT/BLOCK counts over time
- Verdict feed: every flow with label, confidence, novelty, action, reason, SHAP
- Point out a BLOCK event from the DDoS: "99% confidence, SHAP shows SYN flags pushed toward ATTACK"

**Dataset tab:**
- 8 CICIDS-2017 files, 2.37M total rows
- BENIGN: 1,959,818 / ANOMALY: 416,074
- 11 features, stratified sample table

**Models tab (if available):**
- Comparison of RandomForest, XGBoost, IsolationForest
- Metrics: accuracy, macroF1, attack recall, benign false alert rate

**What to say:** "The dashboard gives a complete view: real-time detection, explainability via SHAP, and the training data behind the model."

---

## Step 7: Summary (30 sec)

Wrap up with the architecture:

```
L1 Capture (scapy on wlan0)
  ↓
L2 Flow Table (group packets into flows)
  ↓
L3 Feature Extraction (11 numbers per flow)
  ↓
L4 ML Classification (RandomForest: BENIGN vs ANOMALY)
  ↓
L5 SHAP Explainability (which features pushed the verdict)
  ↓
L6 Decision Engine (whitelist → honeypot → model → alert → allow)
  ↓
L7 Blocking (nftables kernel-level drop)
```

**Key numbers:**
- 99.16% accuracy, 98.99% macro F1
- 99.37% attack recall (catches 99% of attacks)
- <1% benign false alert rate
- Three detection layers: ML classifier + novelty detector + honeypot

**Honest limitations:**
- Trained on CICIDS-2017 (university lab, not real-world internet)
- Can't detect slow low-bandwidth attacks
- Can't analyze encrypted traffic (TLS)
- Single laptop can't simulate real DDoS (needs distributed sensors)

---

## Quick Reference — All Commands

```bash
# Start IPS (detect mode — captures on all interfaces)
sudo .venv/bin/python -m prevention.run_ips --live -d 300 --honeypot

# Start IPS (prevent mode — blocks attackers)
sudo .venv/bin/python -m prevention.run_ips --live -d 300 --prevent --honeypot

# Start dashboard
./run_dashboard.sh

# Trigger honeypot
nc 10.200.130.91 2323

# Run DDoS attack (same machine — sends on loopback)
sudo .venv/bin/python3 scripts/ddos_flood.py --src 10.200.130.91 --target 10.200.130.91

# Check blocked IPs
nft list set ip leon blocked
sudo .venv/bin/python -m prevention.run_ips --list-blocks

# Unblock an IP
sudo .venv/bin/python -m prevention.run_ips --unblock 10.200.130.91
sudo nft delete element ip leon blocked { 10.200.130.91 }

# Block gateway (demo only — breaks internet)
sudo nft add element ip leon blocked { 10.200.130.1 }

# Unblock gateway (restores internet)
sudo nft delete element ip leon blocked { 10.200.130.1 }

# SHAP explanation for a flow
.venv/bin/python -m model.explain --features '{"flow_duration":0.001,"protocol":6,"dst_port":80,"total_fwd_packets":500,"total_bwd_packets":0,"total_fwd_bytes":30000,"total_bwd_bytes":0,"packets_per_second":1000,"syn_count":500,"ack_count":0,"rst_count":0}'

# Retrain models
./train_compare.sh

# Run offline tests
./test_model.sh
./test_dashboard.sh
./test_sensor.sh
./test_prevention.sh
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: scapy` | `.venv/bin/pip install scapy` |
| `nft: permission denied` | Use `sudo` for all IPS and nft commands |
| DDoS shows MAC address warnings | You're using `--src` with a different IP on same machine. Use your own IP: `--src 10.200.130.91` |
| DDoS doesn't trigger BLOCK | Make sure IPS is running with `--prevent`. For same-machine, run IPS **without** `-i` so it captures on lo. |
| Internet doesn't recover after unblock | Run `sudo nft flush set ip leon blocked` to clear all blocks. |
| Dashboard shows no data | Make sure IPS is running and sending WebSocket events. Check `http://127.0.0.1:8050/api/models`. |
| Honeypot shows ALLOW instead of BLOCK | Shouldn't happen — localhost (127.0.0.1) is whitelisted, but wlan0 IP is not. Use wlan0 IP for nc. |
