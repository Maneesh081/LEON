#!/usr/bin/env bash
# LEON sensor - L1 capture -> L2 flows -> L3 features
# usage: ./run_sensor.sh [-i INTERFACE] [-d SECONDS] [-v] [--icmp] [--stage capture|flow|features]
cd "$(dirname "$0")"
sudo .venv/bin/python -m sensor.run_sensor "$@"
