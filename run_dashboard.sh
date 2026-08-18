#!/usr/bin/env bash
# LEON dashboard - live web UI (no root needed)
# usage: ./run_dashboard.sh   ->  open http://127.0.0.1:8050
cd "$(dirname "$0")"
exec .venv/bin/python -m dashboard.server
