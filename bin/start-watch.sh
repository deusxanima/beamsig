#!/usr/bin/env bash
set -euo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
mkdir -p "$LAB/run" "$LAB/logs" "$LAB/archive"
DUR="${1:-5400}"
setsid "$LAB/venv/bin/python" "$LAB/bin/watch-renewal.py" "$DUR" \
  >"$LAB/logs/watch.log" 2>&1 </dev/null &
echo $! > "$LAB/run/watch.pid"
sleep 3
echo "watcher pid=$(cat "$LAB/run/watch.pid")"
cat "$LAB/logs/watch.log"
