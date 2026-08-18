#!/usr/bin/env bash
# LEON model - live prediction (needs root)
# runs sensor capture -> L3 features -> L4 model verdicts
cd "$(dirname "$0")"
exec sudo .venv/bin/python -m model.run_model --live "$@"
