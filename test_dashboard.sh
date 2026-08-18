#!/usr/bin/env bash
# LEON dashboard - offline tests (no root needed)
cd "$(dirname "$0")"
exec .venv/bin/python -m dashboard.test_dashboard
