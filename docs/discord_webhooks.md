# Discord webhook notifications

Every time LEON blocks an IP, it can post a short message to a Discord channel
using a **Discord webhook** — no bot, no token, no developer portal.

This guide covers what a webhook is, how to configure LEON to use one, the
message format, how to test it, and how to troubleshoot when it fails.

---

## 1. What a Discord webhook is

A webhook is a URL that lets you post messages into a specific Discord channel.
It looks like:

```
https://discord.com/api/webhooks/1234567890123456789/AbCdEfGhIjKlMnOpQrStUvWxYz...
```

Key properties:

- **Channel-scoped** — the message goes to exactly one channel; you pick the
  channel when you create the webhook.
- **No bot / no token** — a service simply POSTs a JSON payload to the URL and
  Discord renders it as a normal-looking message.
- **Instantly revocable** — delete the webhook in the server settings and it
  stops working immediately. You can always create a new one.
- **Free** — one per channel, no Discord Nitro or developer application needed.

**Webhook vs. bot:** a bot requires hosting, a token, and bot permissions. A
webhook is just a URL and is the standard way to post one-directional
notifications.

---

## 2. Setup

### 2.1 Create the webhook in Discord

1. Open your Discord server → **Server Settings**.
2. **Integrations → Webhooks → New Webhook**.
3. Give it a name (e.g. `LEON`) and pick the target channel.
4. **Copy Webhook URL**.

### 2.2 Tell LEON about it (one command)

```bash
.venv/bin/python -m prevention.run_ips --set-webhook <DISCORD_WEBHOOK_URL>
```

This writes the URL to `core/leon.json` and prints where it was saved.
No `sudo` is needed for this step.

### 2.3 Verify it was picked up

```bash
.venv/bin/python -m prevention.run_ips --show-notify
```

Expected output (URL shortened for display):

```
webhook: https://discord.com/api/webhooks/12345…
cooldown: 10.0s
source:   core/leon.json (gitignored) or LEON_NOTIFY_DISCORD_WEBHOOK env var
notifications: enabled - discord
```

Now start LEON normally:

```bash
sudo ./run_ips.sh --live -d 60 --prevent --honeypot
```

The startup banner should show:

```
notifications: discord (cooldown 10.0s)
```

Notifications are **on by default** once a webhook is configured — nothing
extra to enable.

---

## 3. Why a file and not an environment variable?

The original design used an env var
(`LEON_NOTIFY_DISCORD_WEBHOOK=...`). Problem: **`sudo` wipes env vars by
default** (`env_reset` in the sudo file for security). LEON runs as root via
`sudo`, so the exported URL never reached the process — the banner showed
`notifications: disabled`.

`sudo -E` doesn't help either: sudo only preserves variables on a whitelist,
and `LEON_NOTIFY_DISCORD_WEBHOOK` isn't on it.

**`sudo` can strip an environment variable, but never a file on disk.** So the
webhook is stored in `core/leon.json`. This works identically on Arch, Linux
Mint, and Ubuntu.

### Security

The webhook URL is effectively a password for one channel:

- `core/leon.json` is in `.gitignore` — the URL is **never committed**.
- A template at `core/leon.example.json` documents the file format for a fresh
  clone.
- Each machine configures its own `core/leon.json` once, via
  `--set-webhook`. Cloning/pulling the repo does **not** bring the secret
  along.
- If a URL ever leaks (chat transcript, screenshot, log), simply delete the
  webhook in Discord and create a new one, then run `--set-webhook` again.

The env var still works as a fallback if you run LEON without `sudo`.

---

## 4. Message format

Notifications are **brief and plain** (no emoji, no clutter). Discord renders
the bold header, and the rest is text:

```
**IP BLOCKED:** 10.123.137.91
Reason: honeypot probe - no real service should be contacted
Source: honeypot | 2026-09-16 00:30:49
```

Where the values come from:

| Line | Source |
|------|--------|
| IP | the blocked address |
| Reason | the `DecisionEngine` reason (same as the terminal + dashboard verdict feed) |
| Source | where the block came from — `rule`, `model`, `honeypot`, `whitelist` |
| Timestamp | local send time (`YYYY-MM-DD HH:MM:SS`) |

Actual HTTP payload:

```json
{"content": "**IP BLOCKED:** 10.123.137.91\nReason: honeypot probe - no real service should be contacted\nSource: honeypot | 2026-09-16 00:30:49"}
```

Implementation: `prevention/notify.py`, `BlockNotifier._message()`.

---

## 5. How it works internally

- `NftablesBlocker` calls an `on_block(ip, reason=..., source=..., timeout=...)`
  callback every time it creates a rule — for firewall blocks, honeypot probes,
  and rules restored at startup.
- `BlockNotifier` is wired as that callback. It builds the message and POSTs it
  to Discord in a **daemon thread**, so a slow or failing webhook can never
  slow down or crash the packet-capture pipeline.
- **Errors are logged, never raised** — a bad URL, HTTP 5xx, or network error
  results in an `ERROR | leon.prevention.notify | ...` log line, nothing more.

---

## 6. Testing

### Offline (no root, no network, no real Discord)

```bash
./test_prevention.sh
```

Look for `ALL NOTIFICATION TESTS PASSED`. The suite mocks `urlopen` and
verifies: payload content, headers, rate limiting, disabled state, the
`on_block` integration, `--set-webhook` round-trips, and the `.gitignore`
entry.

### Live (needs a real webhook)

1. Configure the webhook (`--set-webhook`) and start LEON:
   ```bash
   sudo ./run_ips.sh --live -d 120 --prevent --honeypot
   ```
   Wait for `notifications: discord (cooldown 10.0s)`.
2. From a second terminal, trigger a block — easiest is the honeypot probe
   (use your real interface IP, not `127.0.0.1` which is whitelisted):
   ```bash
   nc <your-ip> 2323
   ```
3. The LEON terminal prints `[HONEYPOT] probe ... -> BLOCK` and within a second
   a message lands in the Discord channel.

Block decision timing note: the honeypot **blocks immediately**, then holds the
attacker's socket open for the dwell window — so the notification appears
instantly, and only after the block is in place.

### Rate limiting

Notifications are throttled by `notify_cooldown` (default **10 seconds**) so a
DDoS flood doesn't spam the channel. Trigger two blocks within 10s → only one
notification. Wait 10s → the next block sends again.

---

## 7. Troubleshooting

### `discord notification failed (...): HTTP Error 403: Forbidden`

The webhook URL + Discord are usually fine; the request is what got rejected.

- **Fixed in LEON:** Python's `urllib` sends `User-Agent: Python-urllib/3.x`
  by default, which Discord's edge returns 403 for. The notifier now sends an
  explicit `User-Agent: LEON-Discord-Notifier/1.0`.
- **Sanity-check with curl** (204 = Discord accepted, 403 on curl = network:
  VPN/ISP/region blocking Discord, not LEON):
  ```bash
  curl -sS -o /dev/null -w "%{http_code}\n" -X POST \
    -H "Content-Type: application/json" -d '{"content":"test"}' \
    "$(python3 -c "import json;print(json.load(open('core/leon.json'))['notify_discord_webhook'])")"
  ```

### `notifications: disabled` on startup

- Run `--show-notify`. `(not set)` means no webhook stored → re-run
  `--set-webhook`. If the URL shows, the file is fine and the banner should
  read `enabled`.
- The env var fallback is wiped by `sudo` — use the file.

### No notification but a BLOCK happened

- Was it within the cooldown window (10s since the last one)? Rate-limited
  sends are skipped (logged as `notification rate-limited`).
- Check the notifier log line: success is `discord notification sent for <ip>`;
  failures are logged with the reason.

### Regenerating / changing the webhook

```bash
.venv/bin/python -m prevention.run_ips --set-webhook <NEW_URL>
```

Overwrites the `notify_discord_webhook` entry in `core/leon.json` and keeps any
other fields (like cooldown) intact.

---

## 8. Configuration reference

| Setting | Storage | Default | Meaning |
|---------|---------|---------|---------|
| `notify_discord_webhook` | `core/leon.json` or `LEON_NOTIFY_DISCORD_WEBHOOK` | unset | webhook URL; notifications on when set |
| `notify_cooldown` | `core/leon.json` or `LEON_NOTIFY_COOLDOWN` | `10` | min seconds between notifications (`0` = no limit) |

---

## 9. Roadmap

**Email (Phase 2)** — the same `BlockNotifier` and `on_block` callbacks, adding
an SMTP branch via `smtplib` (still stdlib, no new deps). Planned env vars:
`LEON_NOTIFY_EMAIL_SMTP_HOST`, `LEON_NOTIFY_EMAIL_SMTP_PORT`,
`LEON_NOTIFY_EMAIL_SMTP_USER`, `LEON_NOTIFY_EMAIL_SMTP_PASS`,
`LEON_NOTIFY_EMAIL_FROM`, `LEON_NOTIFY_EMAIL_TO`.