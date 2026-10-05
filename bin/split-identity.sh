#!/usr/bin/env bash
# Split a Teleport tbot identity file into its component parts.
# Usage: split-identity.sh <identity-file> <outdir>
set -euo pipefail
umask 077

ID_FILE="${1:-${TELEPORT_IDENTITY_FILE:-/var/run/tbot/identity/identity}}"
OUT="${2:-./split}"
mkdir -p "$OUT"
chmod 700 "$OUT"

# 1. Private key block (Teleport wraps it; may be PIV YUBIKEY, EC, or PKCS8)
awk '/-----BEGIN .*PRIVATE KEY-----/{f=1} f{print} /-----END .*PRIVATE KEY-----/{f=0}' \
  "$ID_FILE" > "$OUT/privkey.block"
chmod 600 "$OUT/privkey.block"

# 2. SSH certificate (single line starting with a *-cert-v01@openssh.com keytype)
grep -E '^(ssh|ecdsa|rsa)[^ ]*-cert-v01@openssh\.com ' "$ID_FILE" > "$OUT/ssh-cert.pub" || true

# 3. known_hosts style CA lines
grep -E '^@cert-authority ' "$ID_FILE" > "$OUT/known_hosts.ca" || true

# 4. All X.509 certs, in order. First is the leaf, rest are CA chain.
python3 - "$ID_FILE" "$OUT" <<'PY'
import re, sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text()
out = pathlib.Path(sys.argv[2])
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', src, re.S)
for i, c in enumerate(certs):
    name = "x509-leaf.pem" if i == 0 else f"x509-ca-{i}.pem"
    (out / name).write_text(c + "\n")
print(f"x509 certs found: {len(certs)}")
PY

echo "--- $OUT ---"
ls -la "$OUT"
