#!/usr/bin/env bash
# LEON sensor - live end-to-end test on loopback (needs root)
cd "$(dirname "$0")"
sudo .venv/bin/python -m sensor.test_sensor_live
