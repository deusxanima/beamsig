#!/usr/bin/env bash
# Experiment 6: the x509 / CMS path for arbitrary artifacts.
set -uo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
T="$LAB/exp6"
cd "$T"
CA=tls-user-ca.pem

# window of the cert embedded in artifact.p7s
read -r NB NA < <("$LAB/venv/bin/python" - <<'PY'
import sys
from asn1crypto import cms as c
d = open('$LAB/exp6/artifact.p7s','rb').read()
ci = c.ContentInfo.load(d)
cert = ci['content']['certificates'][0].chosen
import calendar
nb = cert['tbs_certificate']['validity']['not_before'].native
na = cert['tbs_certificate']['validity']['not_after'].native
print(int(nb.timestamp()), int(na.timestamp()))
PY
)
echo "embedded leaf window: $NB ($(date -u -d @$NB +%H:%M:%SZ)) .. $NA ($(date -u -d @$NA +%H:%M:%SZ))"
echo

pass=0; fail=0
check() { local expect="$1" label="$2"; shift 2
  local out rc; out=$("$@" 2>&1); rc=$?
  printf '%-62s rc=%-3s ' "$label" "$rc"
  if { [ "$expect" = ok ] && [ "$rc" -eq 0 ]; } || \
     { [ "$expect" = reject ] && [ "$rc" -ne 0 ]; }; then
    echo "PASS"; pass=$((pass+1))
  else echo "*** UNEXPECTED ***"; fail=$((fail+1)); fi
  echo "$out" | sed 's/^/     | /' | head -3
}

echo "### attached signature ###"
check reject "default purpose (EKU is serverAuth/clientAuth, not emailProtection)" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile "$CA" -out /dev/null
check ok "-purpose any, attime mid-window" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile "$CA" -purpose any \
    -attime $(( (NB+NA)/2 )) -out /dev/null
check reject "-attime 1s BEFORE notBefore" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile "$CA" -purpose any \
    -attime $((NB-1)) -out /dev/null
check reject "-attime 1s AFTER notAfter" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile "$CA" -purpose any \
    -attime $((NA+1)) -out /dev/null
check reject "-attime +1 year" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile "$CA" -purpose any \
    -attime $((NA+31536000)) -out /dev/null
check reject "WRONG CA (tls-host CA)" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile "$LAB/ca/export-tls-host.txt" \
    -purpose any -attime $(( (NB+NA)/2 )) -out /dev/null
check reject "no CA at all (-CAfile /dev/null)" \
  openssl cms -verify -inform DER -in artifact.p7s -CAfile /dev/null \
    -purpose any -attime $(( (NB+NA)/2 )) -out /dev/null

echo
echo "### tampered attached content ###"
"$LAB/venv/bin/python" - <<'PY'
d = bytearray(open('$LAB/exp6/artifact.p7s','rb').read())
i = d.find(b'beam artifact payload v1')
d[i:i+4] = b'BEAM'
open('$LAB/exp6/tampered.p7s','wb').write(bytes(d))
print("flipped embedded content 'beam'->'BEAM' at offset", i)
PY
check reject "tampered embedded content" \
  openssl cms -verify -inform DER -in tampered.p7s -CAfile "$CA" -purpose any \
    -attime $(( (NB+NA)/2 )) -out /dev/null

echo
echo "### detached signature ###"
"$LAB/venv/bin/python" "$LAB/bin/cms-sign.py" artifact.bin -o detached.p7s --detached >/dev/null
read -r DNB DNA < <("$LAB/venv/bin/python" - <<'PY'
from asn1crypto import cms as c
ci = c.ContentInfo.load(open('$LAB/exp6/detached.p7s','rb').read())
v = ci['content']['certificates'][0].chosen['tbs_certificate']['validity']
print(int(v['not_before'].native.timestamp()), int(v['not_after'].native.timestamp()))
PY
)
check ok "detached, correct file (-binary REQUIRED)" \
  openssl cms -verify -inform DER -in detached.p7s -content artifact.bin -binary \
    -CAfile "$CA" -purpose any -attime $(( (DNB+DNA)/2 )) -out /dev/null
printf 'beam artifact payload v2\n' > other.bin
check reject "detached, WRONG file" \
  openssl cms -verify -inform DER -in detached.p7s -content other.bin -binary \
    -CAfile "$CA" -purpose any -attime $(( (DNB+DNA)/2 )) -out /dev/null

echo
echo "### can openssl show us the beam identity? ###"
echo "--- signer subject, as openssl prints it ---"
openssl cms -verify -inform DER -in artifact.p7s -CAfile "$CA" -purpose any \
  -attime $(( (NB+NA)/2 )) -out /dev/null -signer /dev/stdout 2>/dev/null \
  | openssl x509 -noout -subject -nameopt sep_multiline,utf8 2>/dev/null \
  | grep -E '1\.3\.9999|commonName' || echo "(openssl prints custom OIDs numerically)"

echo
echo "==================================================================="
echo "PASS=$pass UNEXPECTED=$fail"
[ "$fail" -eq 0 ]
