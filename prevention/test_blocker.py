"""Offline tests for the L7 nftables blocker (subprocess mocked, no root).

Verifies the exact nft commands issued, family detection, and the
blocks.json persistence round-trip. A live (root) test lives in
test_ips_live.py.
"""
import json
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from core.config import Config
from prevention.blocker import NftablesBlocker, NftablesError

LIST_OUT = (
    'table ip leon {\n'
    '        set blocked {\n'
    '                type ipv4_addr\n'
    '                flags timeout\n'
    '                elements = { 10.0.0.5 timeout 1h, 10.0.0.9 timeout 30m }\n'
    '        }\n'
    '}\n'
)


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def fake_run(calls, list_out=""):
    def _run(cmd, capture_output=True, text=True):
        calls.append(cmd)
        stdout = ""
        if cmd and cmd[1:3] == ["list", "set"]:
            stdout = list_out
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
    return _run


def make_blocker():
    cfg = Config()
    td = tempfile.TemporaryDirectory()
    cfg.blocks_file = str(Path(td.name) / "blocks.json")
    cfg.block_timeout = 60
    return cfg, NftablesBlocker(cfg), td


def test_family_detection():
    print("test: IP -> nftables family detection")
    b = NftablesBlocker()
    chk(b._family_for("10.0.0.5") == "ip", "IPv4 maps to ip")
    chk(b._family_for("2001:db8::1") == "ip6", "IPv6 maps to ip6")
    try:
        b._family_for("not-an-ip")
        raise AssertionError("FAIL: invalid IP accepted")
    except NftablesError:
        print("  ok: invalid IP rejected")


def test_ensure_commands():
    print("test: ensure() builds table/set/chain/rule for v4 + v6")
    cfg, b, td = make_blocker()
    calls = []
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_run(calls)):
        b.ensure()
    cmds = [" ".join(c) for c in calls]
    for want in ("add table ip leon", "add set ip leon blocked",
                 "add chain ip leon input", "add rule ip leon input ip saddr @blocked drop",
                 "add table ip6 leon", "add set ip6 leon blocked6",
                 "add chain ip6 leon input", "add rule ip6 leon input ip6 saddr @blocked6 drop"):
        chk(any(want in c for c in cmds), f"issues: {want}")
    td.cleanup()


def test_block_commands_and_persistence():
    print("test: block() adds element + persists to blocks.json")
    cfg, b, td = make_blocker()
    calls = []
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_run(calls)):
        b.block("10.0.0.5")
    cmds = [" ".join(c) for c in calls]
    chk(any("add element ip leon blocked { 10.0.0.5 timeout 60s }" in c for c in cmds),
        "block element with timeout")
    data = json.loads(Path(cfg.blocks_file).read_text())
    chk("10.0.0.5" in data, "block persisted to blocks.json")
    chk(data["10.0.0.5"]["expires_at"] is not None, "expires_at recorded")
    td.cleanup()


def test_list_blocked_parses():
    print("test: list_blocked() parses nft set output")
    cfg, b, td = make_blocker()
    calls = []
    with mock.patch("prevention.blocker.subprocess.run",
                    side_effect=fake_run(calls, list_out=LIST_OUT)):
        ips = b.list_blocked()
    chk("10.0.0.5" in ips and "10.0.0.9" in ips, f"parsed both IPs, got {ips}")
    td.cleanup()


def test_unblock_command():
    print("test: unblock() deletes the element")
    cfg, b, td = make_blocker()
    calls = []
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_run(calls)):
        b.unblock("10.0.0.5")
    cmds = [" ".join(c) for c in calls]
    chk(any("delete element ip leon blocked { 10.0.0.5 }" in c for c in cmds),
        "delete element command")
    td.cleanup()


def test_restore_reblocks():
    print("test: restore() re-applies unexpired blocks")
    cfg, b, td = make_blocker()
    Path(cfg.blocks_file).write_text(json.dumps({
        "10.0.0.7": {"blocked_at": 1.0, "expires_at": 9999999999},
        "10.0.0.8": {"blocked_at": 1.0, "expires_at": 1.0},  # already expired
    }))
    calls = []
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_run(calls)):
        n = b.restore()
    cmds = [" ".join(c) for c in calls]
    chk(n == 1, f"restored one block, got {n}")
    chk(any("10.0.0.7" in c and "add element" in c for c in cmds), "re-added 10.0.0.7")
    chk(not any("10.0.0.8" in c and "add element" in c for c in cmds), "skipped expired 10.0.0.8")
    td.cleanup()


def test_teardown():
    print("test: teardown() deletes both tables")
    cfg, b, td = make_blocker()
    calls = []
    with mock.patch("prevention.blocker.subprocess.run", side_effect=fake_run(calls)):
        b.teardown()
    cmds = [" ".join(c) for c in calls]
    chk(any("delete table ip leon" in c for c in cmds), "deletes ip leon")
    chk(any("delete table ip6 leon" in c for c in cmds), "deletes ip6 leon")
    td.cleanup()


if __name__ == "__main__":
    test_family_detection()
    test_ensure_commands()
    test_block_commands_and_persistence()
    test_list_blocked_parses()
    test_unblock_command()
    test_restore_reblocks()
    test_teardown()
    print("\nALL BLOCKER TESTS PASSED")
