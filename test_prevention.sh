#!/usr/bin/env bash
# LEON prevention - offline unit tests (no root needed)
cd "$(dirname "$0")"
.venv/bin/python -m prevention.test_decision
.venv/bin/python -m prevention.test_blocker
.venv/bin/python -m prevention.test_honeypot
