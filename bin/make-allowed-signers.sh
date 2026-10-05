#!/usr/bin/env bash
# Build an OpenSSH allowed_signers file from Teleport's exported SSH user CA.
#
# The /webapi/auth/export?type=user response looks like:
#   cert-authority ecdsa-sha2-nistp256 AAAA... clustername=<c>&type=user
# which is NOT valid allowed_signers syntax: allowed_signers requires a
# leading principal pattern, i.e.
#   <principals> cert-authority <keytype> <key>
#
# Usage: make-allowed-signers.sh <principal-pattern> [cluster ...] > allowed_signers
#
# With no cluster, uses $TELEPORT_CLUSTER. Several may be given, so a verifier
# can accept beams from more than one tenant. Note that allowed_signers has no
# way to express which cluster a CA belongs to, so stock ssh-keygen cannot tell
# the tenants apart -- `beamsig verify` does, using a cluster-labelled pin.
set -euo pipefail
PRINCIPALS="${1:-*}"
shift || true
if [ "$#" -eq 0 ]; then
  set -- "${TELEPORT_CLUSTER:?set TELEPORT_CLUSTER or pass a cluster}"
fi

for CLUSTER in "$@"; do
  curl -fsS "https://${CLUSTER}/webapi/auth/export?type=user" \
  | while read -r tag keytype keyb64 rest; do
      [ "$tag" = "cert-authority" ] || continue
      echo "${PRINCIPALS} cert-authority ${keytype} ${keyb64} teleport-user-ca ${CLUSTER} ${rest}"
    done
done
