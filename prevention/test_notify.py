"""Offline tests for block notifications (Discord webhook, no root/network).

Mocks urllib.request.urlopen to avoid real HTTP. Verifies payload content,
rate limiting, disabled state, and the on_block callback integration.
"""
import json
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

from core.config import Config
from prevention.blocker import NftablesBlocker
from prevention.notify import BlockNotifier, save_webhook


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def make_notifier(webhook="https://discord.com/api/webhooks/abc/def", cooldown=0.0):
    cfg = Config()
    cfg.notify_discord_webhook = webhook
    cfg.notify_cooldown = cooldown
    return BlockNotifier(cfg)


def capture_post():
    """Patch urllib.request.urlopen; return (responses_list, done_event, side_effect)."""
    responses: list[dict] = []
    done = threading.Event()

    def side_effect(req, timeout=10):
        responses.append({
            "url": req.full_url,
            "payload": json.loads(req.data),
            "headers": {
                "content-type": req.headers.get("Content-type"),
                "user-agent": req.headers.get("User-agent"),
            },
        })
        done.set()
        resp = mock.MagicMock()
        resp.status = 200
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return resp

    return responses, done, side_effect


# ------------------------------------------------------------------
# tests
# ------------------------------------------------------------------

def test_disabled_noop():
    print("test: disabled notifier (no webhook) is a silent no-op")
    cfg = Config()
    cfg.notify_discord_webhook = None
    n = BlockNotifier(cfg)
    chk(not n.enabled, "enabled is False")
    chk(n.active_channels() == [], "active_channels is empty")
    sent = n.send_block_notification("10.0.0.5")
    chk(not sent, "send returns False")


def test_enabled_post():
    print("test: enabled notifier POSTs JSON to the Discord webhook")
    n = make_notifier(cooldown=0.0)
    chk(n.enabled, "enabled is True")
    responses, done, fake = capture_post()
    with mock.patch("prevention.notify.urllib.request.urlopen", side_effect=fake):
        sent = n.send_block_notification("10.0.0.5", reason="SYN flood (500 SYNs, 0 responses)", source="rule")
    chk(sent, "send accepted")
    chk(done.wait(2.0), "webhook POST completed")
    r = responses[0]
    chk(r["url"] == "https://discord.com/api/webhooks/abc/def", "POSTed to webhook URL")
    content = r["payload"]["content"]
    chk("10.0.0.5" in content, "message contains IP")
    chk("SYN flood" in content, "message contains reason")
    chk("rule" in content, "message contains source")
    chk("IP BLOCKED" in content, "message has IP BLOCKED header")
    h = r["headers"]
    chk(h["content-type"] == "application/json", "Content-Type header is application/json")
    chk(h["user-agent"] == "LEON-Discord-Notifier/1.0",
        "User-Agent header is set (Discord rejects default Python-urllib UA with 403)")


def test_message_fields():
    print("test: _message includes reason when source is None")
    msg = BlockNotifier._message("1.2.3.4", "honeypot probe", None)
    chk("1.2.3.4" in msg, "IP present")
    chk("honeypot probe" in msg, "reason present")
    # source=None → only source line should be "Source: <timestamp>"
    parts = msg.split("\n")
    last_line = parts[-1]
    chk(last_line.startswith("Source: 2"), f"timestamp shown when source is None: {last_line!r}")


def test_rate_limiting():
    print("test: second call within cooldown is skipped")
    n = make_notifier(cooldown=100)
    responses, done, fake = capture_post()
    with mock.patch("prevention.notify.urllib.request.urlopen", side_effect=fake):
        sent1 = n.send_block_notification("10.0.0.5")
        time.sleep(0.01)
        sent2 = n.send_block_notification("10.0.0.9")
    chk(sent1, "first call accepted")
    chk(not sent2, "second call rate-limited")
    chk(done.wait(2.0), "webhook POST completed")
    chk(len(responses) == 1, f"only one POST sent, got {len(responses)}")
    chk("10.0.0.5" in responses[0]["payload"]["content"], "first IP sent")
    # reset to avoid rate-limiting other tests
    n._last_sent = 0.0


def test_cooldown_reset():
    print("test: second call succeeds after cooldown elapses")
    n = make_notifier(cooldown=0.05)
    responses, done, fake = capture_post()
    with mock.patch("prevention.notify.urllib.request.urlopen", side_effect=fake):
        n.send_block_notification("10.0.0.5")
        done.wait(2.0)
        time.sleep(0.06)
        done.clear()
        responses.clear()
        sent2 = n.send_block_notification("10.0.0.9")
    chk(sent2, "second call accepted after cooldown")
    chk(done.wait(2.0), "webhook POST completed")
    chk("10.0.0.9" in responses[0]["payload"]["content"], "second IP sent")


def test_http_error_does_not_crash():
    print("test: HTTP 500 from Discord is logged, not raised")
    n = make_notifier(cooldown=0.0)
    errors = []
    done = threading.Event()

    def bad_open(req, timeout=10):
        done.set()
        raise RuntimeError("discord webhook returned HTTP 500")

    with mock.patch("prevention.notify.urllib.request.urlopen", side_effect=bad_open):
        with mock.patch("prevention.notify.log.error", side_effect=lambda *a: errors.append(a)):
            n.send_block_notification("10.0.0.5")
            done.wait(2.0)
            time.sleep(0.05)
    chk(any("discord notification failed" in str(e) for e in errors), "error was logged")


def test_blocker_callback_fires():
    print("test: NftablesBlocker.on_block fires on block() with reason + source")
    cfg = Config()
    cfg.blocks_file = "/tmp/leon_test_blocks_notify.json"
    cfg.block_timeout = 60
    captured = []
    callback_done = threading.Event()

    def on_block(ip, reason=None, source=None, timeout=None):
        captured.append({"ip": ip, "reason": reason, "source": source, "timeout": timeout})
        callback_done.set()

    calls = []

    def fake_subprocess(cmd, capture_output=True, text=True):
        calls.append(cmd)
        return mock.MagicMock(returncode=0, stdout="", stderr="")

    b = NftablesBlocker(cfg, on_block=on_block)
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_subprocess):
        b.block("10.0.0.5", reason="SYN flood (500 SYNs, 0 responses)", source="rule")
    callback_done.wait(1.0)
    chk(captured, "on_block was called")
    chk(captured[0]["ip"] == "10.0.0.5", "IP passed correctly")
    chk(captured[0]["reason"] == "SYN flood (500 SYNs, 0 responses)", "reason passed correctly")
    chk(captured[0]["source"] == "rule", "source passed correctly")


def test_blocker_callback_exception_does_not_crash():
    print("test: on_block callback exception is caught and logged")
    cfg = Config()
    cfg.blocks_file = "/tmp/leon_test_blocks_notify_ex.json"
    cfg.block_timeout = 60
    errors = []

    def bad_callback(ip, **kw):
        raise ValueError("boom")

    calls = []

    def fake_subprocess(cmd, capture_output=True, text=True):
        calls.append(cmd)
        return mock.MagicMock(returncode=0, stdout="", stderr="")

    b = NftablesBlocker(cfg, on_block=bad_callback)
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_subprocess):
        with mock.patch("prevention.blocker.log.error", side_effect=lambda *a: errors.append(a)):
            ok = b.block("10.0.0.5")
    chk(ok, "block() still returned True despite callback error")
    chk(any("on_block callback failed" in str(e) for e in errors), "error logged")


def test_acceptance_count():
    print("test: _accepted and _sent counts are correct")
    n = make_notifier(cooldown=0.0)
    responses, done, fake = capture_post()
    with mock.patch("prevention.notify.urllib.request.urlopen", side_effect=fake):
        n.send_block_notification("10.0.0.5")
        done.wait(2.0)
        time.sleep(0.05)
    chk(n._accepted == 1, "accepted count is 1")
    chk(n._sent == 1, "sent count is 1")


def test_save_webhook_roundtrip():
    print("test: save_webhook() writes a file that load_json() picks up")
    td = Path(tempfile.mkdtemp()) / "leon.json"
    save_webhook("https://discord.com/api/webhooks/abc/def", path=str(td))
    data = json.loads(td.read_text())
    chk(data["notify_discord_webhook"] == "https://discord.com/api/webhooks/abc/def",
        "webhook persisted to JSON")
    cfg = Config()
    cfg.load_json(str(td))
    chk(cfg.notify_discord_webhook == "https://discord.com/api/webhooks/abc/def",
        "load_json() restores the webhook")


def test_save_webhook_keeps_existing_fields():
    print("test: save_webhook() preserves other config fields")
    td = Path(tempfile.mkdtemp()) / "leon.json"
    td.write_text(json.dumps({"notify_cooldown": 30}))
    save_webhook("https://discord.com/api/webhooks/xyz/123", path=str(td))
    data = json.loads(td.read_text())
    chk(data["notify_cooldown"] == 30, "existing cooldown preserved")
    chk(data["notify_discord_webhook"] == "https://discord.com/api/webhooks/xyz/123",
        "webhook added alongside existing fields")


def test_leon_json_gitignored():
    print("test: core/leon.json is listed in .gitignore (URL stays private)")
    gi = Path(".gitignore").read_text()
    chk("core/leon.json" in gi, "core/leon.json is gitignored")


if __name__ == "__main__":
    test_disabled_noop()
    test_enabled_post()
    test_message_fields()
    test_rate_limiting()
    test_cooldown_reset()
    test_http_error_does_not_crash()
    test_blocker_callback_fires()
    test_blocker_callback_exception_does_not_crash()
    test_acceptance_count()
    test_save_webhook_roundtrip()
    test_save_webhook_keeps_existing_fields()
    test_leon_json_gitignored()
    print("\nALL NOTIFICATION TESTS PASSED")
