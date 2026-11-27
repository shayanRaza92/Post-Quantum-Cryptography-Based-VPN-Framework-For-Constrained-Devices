#!/usr/bin/env bash
# Runs the laptop-side gateway benchmark (tests L0-L6) 3 times and keeps each run.
#   bash benchmarking/system_benchmark/run_laptop_3x.sh        (run from PQC_VPN/ or Non_PQC_VPN/)
# Plug the laptop in and select the Performance power mode first: on battery / power-saver the
# CPU is slowed down and every laptop timing would look worse.
set -euo pipefail
cd "$(dirname "$0")"
if [ "$(cat /sys/class/power_supply/A*/online 2>/dev/null | head -1)" = "0" ]; then
  echo "The laptop is on battery. Plug it in (and choose Performance mode), then run this again."; exit 1
fi
for i in 1 2 3; do
  out="results/laptop_gateway_results_run$i.csv"
  if [ -e "$out" ]; then echo "$out already exists, skipping"; continue; fi
  echo "=== laptop run $i of 3 ==="
  python3 gateway_benchmark.py
  mv results/laptop_gateway_results.csv "$out"
  sleep 10
done
echo "Done: results/laptop_gateway_results_run{1,2,3}.csv"
