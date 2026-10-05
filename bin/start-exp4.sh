#!/usr/bin/env bash
set -euo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
setsid "$LAB/bin/exp4-driver.sh" >"$LAB/logs/exp4-driver.log" 2>&1 </dev/null &
echo $! > "$LAB/run/exp4.pid"
sleep 2
echo "driver pid=$(cat "$LAB/run/exp4.pid")"; cat "$LAB/logs/exp4-driver.log"
