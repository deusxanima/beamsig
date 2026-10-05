#!/usr/bin/env bash
# Drive experiment 4 across a tbot renewal and a certificate expiry.
set -uo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
export SSH_AUTH_SOCK="$LAB/run/agent.sock"

wait_until() { # wait_until <unixtime>
  local t="$1"
  while [ "$(date -u +%s)" -lt "$t" ]; do sleep 10; done
}

# the identity currently in place expires here; renewals land every 20 min
read -r VA VB < <("$LAB/venv/bin/python" -c "
import sys; sys.path.insert(0,'$LAB')
from beamsig import identity, sshcert
c=sshcert.parse_line(identity.load().ssh_cert_line)
print(c.valid_after, c.valid_before)")

# next renewal = valid_after + 20 min (+30s slack)
NEXT=$((VA + 1200 + 30))
echo "[driver] waiting for renewal at $(date -u -d @$NEXT +%H:%M:%SZ)"
wait_until "$NEXT"
"$LAB/bin/exp4-renewal.sh" commit "gen-B (after tbot renewal)"

# wait for the ORIGINAL demo-repo cert (14:36:27..15:37:27) to expire, +90s
DEMO_EXP=1791214647
EXP=$((DEMO_EXP + 90))
echo "[driver] waiting for the first cert to EXPIRE at $(date -u -d @$EXP +%H:%M:%SZ)"
wait_until "$EXP"

{
  echo
  echo "###############################################################"
  echo "# POST-EXPIRY VERIFICATION  $(date -u +%H:%M:%SZ)"
  echo "###############################################################"
  echo "## repos/demo HEAD~2 (51fbefe) was signed with cert 14:36:27..15:37:27"
  echo "## that certificate is now EXPIRED. Does the commit still verify?"
  echo "--- git verify-commit ---"
  git -C "$LAB/repos/demo" verify-commit 51fbefe 2>&1; echo "rc=$?"
  echo "--- beamsig verify-commit ---"
  "$LAB/bin/beamsig" verify-commit 51fbefe -C "$LAB/repos/demo" \
    --ca "$LAB/ca/pinned-user-ca.txt" --beam-id "$BEAM_ID" 2>&1 \
    | grep -E "result|claimed|cert valid"; echo "rc=$?"
  echo
  echo "--- ssh-keygen -Y verify with verify-time = NOW (no commit context) ---"
  cd "$LAB/exp2"
  ssh-keygen -Y verify -f allowed_signers -I root -n git -s sig-from-cert.sig < msg.txt 2>&1
  echo "rc=$?"
  echo "(sig-from-cert.sig used the same 14:36:27..15:37:27 cert; with no"
  echo " -Overify-time, ssh-keygen defaults to NOW and must now reject it)"
} >> "$LAB/logs/exp4-renewal.txt" 2>&1

"$LAB/bin/exp4-renewal.sh" verify
echo "[driver] done" >> "$LAB/logs/exp4-renewal.txt"
