#!/usr/bin/env bash
# Build an OpenSSH allowed_signers file from Teleport's exported SSH user CA.
#
# The /webapi/auth/export?type=user response looks like:
#   cert-authority ecdsa-sha2-nistp256 AAAA... clustername=<c>&type=user
# which is NOT valid allowed_signers syntax: allowed_signers requires a
# leading principal pattern, i.e.
#   <principals> cert-authority <keytype> <key>
#
# Usage: make-allowed-signers.sh [cluster] [principal-pattern] > allowed_signers
set -euo pipefail
CLUSTER="${1:-${TELEPORT_CLUSTER:?set TELEPORT_CLUSTER}}"
PRINCIPALS="${2:-*}"

curl -fsS "https://${CLUSTER}/webapi/auth/export?type=user" \
| while read -r tag keytype keyb64 rest; do
    [ "$tag" = "cert-authority" ] || continue
    echo "${PRINCIPALS} cert-authority ${keytype} ${keyb64} teleport-user-ca ${CLUSTER} ${rest}"
  done
