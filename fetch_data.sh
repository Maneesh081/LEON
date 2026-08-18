#!/usr/bin/env bash
# LEON - download the 8 cleaned CICIDS2017 CSVs (teammate A26D/LEON) for training
# ~117 MB total, fetched from raw.githubusercontent.com
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p model/data/cleaned
BASE="https://raw.githubusercontent.com/A26D/LEON/main/data/cleaned"
FILES=(
  Monday-WorkingHours_cleaned.csv
  Tuesday-WorkingHours_cleaned.csv
  Wednesday-workingHours_cleaned.csv
  Thursday-WorkingHours-Morning-WebAttacks_cleaned.csv
  Thursday-WorkingHours-Afternoon-Infilteration_cleaned.csv
  Friday-WorkingHours-Morning_cleaned.csv
  Friday-WorkingHours-Afternoon-PortScan_cleaned.csv
  Friday-WorkingHours-Afternoon-DDos_cleaned.csv
)
for f in "${FILES[@]}"; do
  if [ -f "model/data/cleaned/$f" ]; then
    echo "skip (exists): $f"
    continue
  fi
  echo "downloading: $f"
  curl -sSL -o "model/data/cleaned/$f" "$BASE/$f"
done
echo
echo "done. files:"
ls -la model/data/cleaned
