#!/usr/bin/env bash
# LEON prevention/IPS - full pipeline: capture -> classify -> decide -> (block)
# needs root for raw sockets + nftables
# usage: ./run_ips.sh --live -i INTERFACE -d SECONDS [--prevent] [--honeypot]
cd "$(dirname "$0")"
exec sudo .venv/bin/python -m prevention.run_ips "$@"
