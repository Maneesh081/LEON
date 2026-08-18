#!/usr/bin/env bash
# LEON model - train RF vs XGBoost vs IsolationForest comparison
# usage: ./train_compare.sh [--per-class N] [--quick]
cd "$(dirname "$0")"
.venv/bin/python -m model.train_compare "$@"
