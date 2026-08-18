#!/usr/bin/env bash
# LEON prevention - live nftables test (needs root)
cd "$(dirname "$0")"
exec sudo .venv/bin/python -m prevention.test_ips_live
