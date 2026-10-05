#!/usr/bin/env bash
# Install and configure beamsig on a Beam.
#
# Makes every git repository on this Beam sign its commits with the Beam's own
# Teleport identity, and makes `git log` report which Beam signed. Verification
# chains to the cluster's SSH user CA, so a signature stays checkable offline
# after the Beam and its certificates are gone.
#
# This runs ON the Beam and assumes beamsig has been copied here already: it
# never clones, fetches or reaches any git remote, because a Beam is not
# guaranteed to have credentials for one. Use ./main.sh <beam> from a machine
# that has the checkout; it copies this script plus a tarball of the tree.
#
# Source is taken from, in order:
#   1. the directory containing this script, if it looks like a beamsig tree
#   2. beamsig.tar.gz (or $BEAMSIG_TARBALL) sitting next to this script
#
# Usage:
#   setup-beamsig.sh                 install
#   setup-beamsig.sh --no-autosign   install, but don't sign by default
#   setup-beamsig.sh --no-showsig    install, but don't show sigs in git log
#   setup-beamsig.sh --uninstall     remove everything this installed
#
# Environment:
#   BEAMSIG_DIR      install location  (default $HOME/.beamsig)
#   BEAMSIG_TARBALL  explicit tarball path
#
# Everything it writes lives in $BEAMSIG_DIR, ~/.config/beamsig and the beamsig
# keys in ~/.gitconfig. Nothing persists beyond the Beam.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DIR="${BEAMSIG_DIR:-$HOME/.beamsig}"
CFG="${BEAMSIG_CONFIG_DIR:-$HOME/.config/beamsig}"
INSTALL_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --no-autosign | --no-showsig) INSTALL_ARGS+=("$arg") ;;
        --uninstall)
            if [[ -x "$DIR/bin/install-global.sh" ]]; then
                "$DIR/bin/install-global.sh" --uninstall
            else
                echo "note: $DIR/bin/install-global.sh missing; clearing git keys directly"
                for k in user.name user.email gpg.format gpg.ssh.program \
                    gpg.ssh.allowedSignersFile user.signingkey \
                    commit.gpgsign tag.gpgsign log.showSignature; do
                    git config --global --unset-all "$k" 2>/dev/null || true
                done
            fi
            rm -rf "$DIR" "$CFG"
            printf 'Removed %s and %s\n' "$DIR" "$CFG"
            exit 0
            ;;
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

# No git remote access is needed, and no tsh. curl reaches the cluster's public
# CA export endpoint, which any Beam can do.
for cmd in git curl tar python3 ssh-keygen openssl; do
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
STAGED_TARBALL=""

if [[ -f "$HERE/bin/setup.sh" && -f "$HERE/beamsig/cli.py" ]]; then
    # Already unpacked, and this script lives inside the tree.
    if [[ "$HERE" != "$DIR" ]]; then
        printf 'Installing from %s into %s\n' "$HERE" "$DIR"
        mkdir -p "$DIR"
        tar -C "$HERE" -cf - \
            --exclude=./venv --exclude=./.git --exclude=./run \
            --exclude='*.pyc' --exclude=__pycache__ . | tar -C "$DIR" -xf -
    else
        printf 'Using beamsig tree in place at %s\n' "$DIR"
    fi
else
    TARBALL="${BEAMSIG_TARBALL:-$HERE/beamsig.tar.gz}"
    test -f "$TARBALL" || {
        echo "error: no beamsig source found." >&2
        echo "       Looked for a tree at $HERE and a tarball at $TARBALL." >&2
        echo "       Run ./main.sh <beam> from a machine holding the checkout;" >&2
        echo "       it copies this script and a tarball of the tree across." >&2
        exit 1
    }
    printf 'Unpacking %s into %s\n' "$TARBALL" "$DIR"
    # Replace any previous install rather than merging into it, so a stale file
    # from an older copy cannot survive and be picked up.
    rm -rf "$DIR"
    mkdir -p "$DIR"
    tar -xzf "$TARBALL" -C "$DIR"
    # A tarball made with `tar czf ... .` unpacks flat; one made from a parent
    # directory nests. Flatten that case so paths below are predictable.
    if [[ ! -f "$DIR/bin/setup.sh" ]]; then
        inner="$(find "$DIR" -mindepth 2 -maxdepth 2 -type f -path '*/bin/setup.sh' \
            -printf '%h\n' | head -1)"
        inner="${inner%/bin}"
        if [[ -n "$inner" && -d "$inner" ]]; then
            shopt -s dotglob
            mv "$inner"/* "$DIR"/
            shopt -u dotglob
            rmdir "$inner" 2>/dev/null || true
        fi
    fi
    STAGED_TARBALL="$TARBALL"
fi

test -f "$DIR/bin/setup.sh" || {
    echo "error: $DIR does not look like a beamsig tree (no bin/setup.sh)" >&2
    exit 1
}
chmod +x "$DIR"/bin/* "$DIR"/setup-beamsig.sh 2>/dev/null || true
echo

# --- build + configure ----------------------------------------------------
# setup.sh builds the venv, generates the hardware key agent gRPC stubs and
# exports the cluster CAs. install-global.sh writes ~/.gitconfig.
BEAMSIG_HOME="$DIR" "$DIR/bin/setup.sh"
echo
BEAMSIG_HOME="$DIR" "$DIR/bin/install-global.sh" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}

# --- smoke test -----------------------------------------------------------
# Prove the whole chain end to end rather than assuming it: sign a real commit
# in a throwaway repository and verify it against the pinned CA.
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
    --ca "$CFG/pinned-user-ca.txt" --beam-id "$BEAM_ID" >/dev/null

printf 'Signed and verified as beam-%s\n' "$BEAM_ID"

# Transfer artifacts have served their purpose; don't leave them lying around.
if [[ -n "$STAGED_TARBALL" ]]; then
    rm -f "$STAGED_TARBALL"
fi

cat <<EOF

beamsig is ready.

  installed       $DIR
  signer          beam-$BEAM_ID
  alias           $BEAM_ALIAS (self-reported; it is in no certificate)
  trust anchor    $CFG/pinned-user-ca.txt

  git commit      signed automatically
  git log         shows the beam that signed
  $DIR/bin/beamsig --help

Read $DIR/REPORT.md before relying on a signature. In particular: the
certificate's Key ID is the Beam's *owner*, not the Beam; anything running in
the Beam can sign as the Beam; and because the key never rotates while the
certificate does, a signer can choose which validity window a verifier sees.

Nothing here outlives the Beam. To remove it now:
  $DIR/setup-beamsig.sh --uninstall
EOF
