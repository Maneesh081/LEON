#!/usr/bin/env bash
# LEON sensor - offline unit tests for L1+L2+L3 (no root needed)
cd "$(dirname "$0")"
.venv/bin/python -m sensor.test_sensor
