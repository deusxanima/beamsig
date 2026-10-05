#!/usr/bin/env bash
# Create the virtualenv, generate the gRPC stubs, and fetch the Teleport CAs.
# Everything beamsig needs to run from a fresh clone.
set -euo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
cd "$LAB"

if ! python3 -c 'import ensurepip' 2>/dev/null; then
  echo "python3 venv module missing; install it first:"
  echo "  sudo apt-get install -y python3-venv"
  exit 1
fi

if [ ! -x venv/bin/python ]; then
  echo "== creating venv =="
  python3 -m venv venv
fi
echo "== installing requirements =="
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q -r requirements.txt

echo "== generating hardware key agent gRPC stubs =="
mkdir -p gen
./venv/bin/python -m grpc_tools.protoc -Iproto \
  --python_out=gen --grpc_python_out=gen --pyi_out=gen \
  proto/teleport/hardwarekeyagent/v1/hardwarekeyagent_service.proto
touch gen/teleport/__init__.py \
      gen/teleport/hardwarekeyagent/__init__.py \
      gen/teleport/hardwarekeyagent/v1/__init__.py

if [ -n "${TELEPORT_CLUSTER:-}" ]; then
  echo "== exporting Teleport CAs from $TELEPORT_CLUSTER =="
  mkdir -p ca
  for t in user host tls-user tls-host; do
    curl -fsS "https://${TELEPORT_CLUSTER}/webapi/auth/export?type=$t" \
      -o "ca/export-$t.txt" && echo "  ca/export-$t.txt"
  done
  cp ca/export-user.txt ca/pinned-user-ca.txt
  ./bin/make-allowed-signers.sh "$TELEPORT_CLUSTER" 'beams' > ca/allowed_signers
  echo "  ca/allowed_signers"
  # the SSH certificate, for git's user.signingkey. Must be the CERTIFICATE:
  # pointing user.signingkey at a bare key silently drops all beam identity.
  ./bin/split-identity.sh "${TELEPORT_IDENTITY_FILE:-/var/run/tbot/identity/identity}" \
    ca/split >/dev/null
  cp ca/split/ssh-cert.pub ca/beam-cert.pub
  echo "  ca/beam-cert.pub"
else
  echo "== TELEPORT_CLUSTER unset, skipping CA export =="
fi

echo
echo "Done. Next:"
echo "  ./bin/start-agent.sh                 # ssh-agent shim over the hardware key agent"
echo "  ./bin/beamsig --help"
