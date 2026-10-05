#!/usr/bin/env bash
# Start the beamsig ssh-agent shim fully detached.
set -euo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
mkdir -p "$LAB/run" "$LAB/logs"
if [ -f "$LAB/run/agent.pid" ] && kill -0 "$(cat "$LAB/run/agent.pid")" 2>/dev/null; then
  echo "already running pid $(cat "$LAB/run/agent.pid")"
  exit 0
fi
setsid "$LAB/bin/beamsig-agent" "$LAB/run/agent.sock" \
  >"$LAB/logs/agent.log" 2>&1 </dev/null &
echo $! > "$LAB/run/agent.pid"
sleep 2
echo "pid=$(cat "$LAB/run/agent.pid")"
cat "$LAB/logs/agent.log"
