"""Live nftables test - needs root.

ensure -> block -> verify in the real kernel -> unblock -> teardown, plus a
persistence/restore round-trip. Run with: sudo .venv/bin/python -m prevention.test_ips_live
"""
import subprocess
import tempfile
from pathlib import Path

from core.config import Config
from prevention.blocker import NftablesBlocker


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def main() -> int:
    import os
    if os.geteuid() != 0:
        print("needs root: run with sudo .venv/bin/python -m prevention.test_ips_live")
        return 2

    cfg = Config()
    td = tempfile.TemporaryDirectory()
    cfg.blocks_file = str(Path(td.name) / "blocks.json")
    cfg.block_timeout = 60
    b = NftablesBlocker(cfg)
    b.teardown()  # clean slate

    b.ensure()
    b.block("127.0.0.1", timeout=60)
    ips = b.list_blocked()
    chk("127.0.0.1" in ips, f"block visible via list_blocked, got {ips}")

    proc = subprocess.run(["nft", "list", "set", "ip", "leon", "blocked"],
                          capture_output=True, text=True)
    chk("127.0.0.1" in proc.stdout, "block verified directly with nft")

    b2 = NftablesBlocker(cfg)
    n = b2.restore()
    chk(n == 1, f"fresh blocker restored the persisted block ({n})")
    chk("127.0.0.1" in b2.list_blocked(), "restored block is live in the kernel")

    b.unblock("127.0.0.1")
    chk("127.0.0.1" not in b.list_blocked(), "unblocked cleanly")

    b.teardown()
    chk(b.list_blocked() == [], "all blocks gone after teardown")
    td.cleanup()
    print("\nALL LIVE IPS TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
