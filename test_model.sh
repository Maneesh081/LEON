#!/usr/bin/env bash
# LEON model - offline unit tests (no root needed)
cd "$(dirname "$0")"
.venv/bin/python -m model.test_model
