#!/usr/bin/env bash
# Install and configure beamsig for a fresh Beam.
#
# Makes every git repository in this Beam sign its commits with the Beam's own
# Teleport identity, and makes `git log` report which Beam signed. Verification
# chains to the cluster's SSH user CA, so a signature stays checkable offline
# after the Beam and its certificates are gone.
#
# This script is self-contained: copy just this file onto a Beam and run it. It
# clones the beamsig repository itself.
#
# Usage:
#   ./setup-beamsig.sh                 clone (or update) and configure
#   ./setup-beamsig.sh --no-autosign   configure, but don't sign by default
#   ./setup-beamsig.sh --no-showsig    configure, but don't show sigs in git log
#
# Environment:
#   BEAMSIG_REPO  git URL to clone      (default beams@boros:beamsign.git)
#   BEAMSIG_DIR   checkout location     (default $HOME/beamsig)
#   BEAMSIG_REF   branch/ref to check out (default: the remote's default)
set -euo pipefail

REPO="${BEAMSIG_REPO:-beams@boros:beamsign.git}"
DIR="${BEAMSIG_DIR:-$HOME/beamsig}"
REF="${BEAMSIG_REF:-}"
INSTALL_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --no-autosign | --no-showsig) INSTALL_ARGS+=("$arg") ;;
        *)
            echo "error: unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

: "${HOME:?HOME must be set}"
: "${BEAM_ID:?BEAM_ID is not set; run this on a Beam}"
: "${BEAM_ALIAS:?BEAM_ALIAS is not set; run this on a Beam}"
: "${TELEPORT_CLUSTER:?TELEPORT_CLUSTER is not set; run this on a Beam}"

for cmd in git tsh curl python3 ssh-keygen openssl; do
    command -v "$cmd" >/dev/null || {
        echo "error: $cmd is required" >&2
        exit 1
    }
done

# The Beam's own credential. Everything below depends on it, and on the agent
# that holds the (non-exportable) private key it refers to.
IDENTITY="${TELEPORT_IDENTITY_FILE:-/var/run/tbot/identity/identity}"
AGENT_DIR="${TELEPORT_KEY_AGENT_DIR:-/var/run/tbot/identity}"

test -r "$IDENTITY" || {
    echo "error: cannot read the tbot identity file: $IDENTITY" >&2
    echo "       beamsig signs with the Beam's Teleport certificate; without" >&2
    echo "       this file there is nothing to sign with." >&2
    exit 1
}
test -S "$AGENT_DIR/agent.sock" || {
    echo "error: no hardware key agent socket at $AGENT_DIR/agent.sock" >&2
    echo "       The identity file holds a PIV slot reference, not a private" >&2
    echo "       key. Signing is impossible without this agent." >&2
    exit 1
}

printf 'Configuring beamsig for beam %s (%s) on %s\n\n' \
    "$BEAM_ALIAS" "$BEAM_ID" "$TELEPORT_CLUSTER"

# --- prerequisites --------------------------------------------------------
# beamsig needs grpcio (to speak to Teleport's hardware key agent), cryptography
# and asn1crypto, none of which ship with the Beam image, so it runs out of a
# virtualenv. Debian splits the venv module into its own package.
install_venv_pkg() {
    local versioned
    versioned="python3.$(python3 -c 'import sys; print(sys.version_info.minor)')-venv"
    sudo apt-get install -y -q python3-venv >/dev/null 2>&1 ||
        sudo apt-get install -y -q "$versioned" >/dev/null 2>&1
}

if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    echo "Installing python3-venv..."
    # A fresh Beam image can ship with no apt package lists at all, in which
    # case the install fails with "has no installation candidate". Only pay for
    # `apt-get update` when that happens.
    if ! install_venv_pkg; then
        echo "Refreshing package lists..."
        sudo apt-get update -q >/dev/null
        install_venv_pkg || {
            echo "error: could not install the python3 venv package" >&2
            exit 1
        }
    fi
fi
python3 -c 'import ensurepip' >/dev/null 2>&1 || {
    echo "error: python3 venv module still unavailable" >&2
    exit 1
}

# --- source ---------------------------------------------------------------
# Pushing and cloning go through Teleport, so git must use `tsh ssh` as its
# transport. Persist it in the clone rather than relying on the caller's
# environment, otherwise a later `git push` from a plain shell fails to
# resolve the host.
if [[ -d "$DIR/.git" ]]; then
    printf 'Updating existing checkout at %s\n' "$DIR"
    git -C "$DIR" config core.sshCommand "tsh ssh"
    git -C "$DIR" remote set-url origin "$REPO"
    git -C "$DIR" fetch --quiet origin
    if [[ -n "$REF" ]]; then
        git -C "$DIR" checkout --quiet "$REF"
    fi
    # Only fast-forward; never discard local work during setup.
    git -C "$DIR" merge --ff-only --quiet '@{u}' 2>/dev/null ||
        echo "note: left local commits in place (no fast-forward)"
else
    printf 'Cloning %s into %s\n' "$REPO" "$DIR"
    GIT_SSH_COMMAND="tsh ssh" git clone --quiet "$REPO" "$DIR"
    git -C "$DIR" config core.sshCommand "tsh ssh"
    if [[ -n "$REF" ]]; then
        git -C "$DIR" checkout --quiet "$REF"
    fi
fi
printf 'At %s\n\n' "$(git -C "$DIR" log --no-show-signature --oneline -1)"

# --- build + configure ----------------------------------------------------
# setup.sh builds the venv, generates the hardware key agent gRPC stubs and
# exports the cluster CAs. install-global.sh writes ~/.gitconfig.
"$DIR/bin/setup.sh"
echo
"$DIR/bin/install-global.sh" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}

# --- smoke test -----------------------------------------------------------
# Prove the whole chain end to end rather than assuming it: sign a real commit
# in a throwaway repository and verify it against the pinned CA. Done in a temp
# directory so nothing is left behind.
echo
echo "Verifying end to end..."
SMOKE="$(mktemp -d)"
trap 'rm -rf "$SMOKE"' EXIT

git init --quiet "$SMOKE"
echo beamsig >"$SMOKE/canary"
git -C "$SMOKE" add canary
git -C "$SMOKE" commit --quiet -m "beamsig setup smoke test"

status="$(git -C "$SMOKE" log --no-show-signature -1 --format='%G?')"
signer="$(git -C "$SMOKE" log --no-show-signature -1 --format='%GS')"

if [[ "$status" != "G" || "$signer" != "beam-$BEAM_ID" ]]; then
    echo "error: smoke test failed: expected G / beam-$BEAM_ID," >&2
    echo "       got '$status' / '$signer'" >&2
    git -C "$SMOKE" log --show-signature -1 >&2 || true
    exit 1
fi

# And confirm the independent verifier agrees, including the beam-specific
# checks git cannot make (pinned CA, bot-name must be a beam, commit time
# inside the certificate window).
"$DIR/bin/beamsig" verify-commit HEAD -C "$SMOKE" \
    --ca "$HOME/.config/beamsig/pinned-user-ca.txt" \
    --beam-id "$BEAM_ID" >/dev/null

printf 'Signed and verified as beam-%s\n' "$BEAM_ID"

cat <<EOF

beamsig is ready.

  repository      $DIR
  signer          beam-$BEAM_ID
  alias           $BEAM_ALIAS (self-reported; it is in no certificate)
  trust anchor    $HOME/.config/beamsig/pinned-user-ca.txt

  git commit      signed automatically
  git log         shows the beam that signed
  $DIR/bin/beamsig --help

Read $DIR/REPORT.md before relying on a signature. In particular: the
certificate's Key ID is the Beam's *owner*, not the Beam; anything running in
the Beam can sign as the Beam; and because the key never rotates while the
certificate does, a signer can choose which validity window a verifier sees.

Undo with: $DIR/bin/install-global.sh --uninstall
EOF
