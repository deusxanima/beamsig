#!/usr/bin/env bash
# Install beamsig onto a Beam, from a machine that has this checkout.
#
#   ./main.sh <beam> [--no-autosign] [--no-showsig]
#   ./main.sh <beam> --uninstall
#
# <beam> is an alias or UUID, anything `tsh beams exec` accepts.
#
# The target Beam is assumed to have NO git remote credentials, so nothing is
# cloned there. This packs the working tree (minus the virtualenv and other
# generated files), copies it plus setup-beamsig.sh with `tsh beams scp`, and
# runs the setup script over `tsh beams exec`.
set -euo pipefail

usage() {
    echo "usage: $0 <beam> [--no-autosign] [--no-showsig] [--uninstall]" >&2
    exit 2
}

BEAM="${1:-}"
[[ -n "$BEAM" && "$BEAM" != -* ]] || usage
shift

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_STAGE="/tmp/beamsig-install"

command -v tsh >/dev/null || {
    echo "error: tsh is required" >&2
    exit 1
}
test -f "$HERE/setup-beamsig.sh" || {
    echo "error: setup-beamsig.sh not found next to $0" >&2
    exit 1
}

# --uninstall needs no payload; the script is already on the Beam from install.
# `tsh beams exec` re-splits its arguments, so quoted shell one-liners such as
# `bash -c '...'` arrive mangled. Only ever invoke a script by path.
for arg in "$@"; do
    if [[ "$arg" == "--uninstall" ]]; then
        echo "==> uninstalling on $BEAM"
        tsh beams exec "$BEAM" -- bash "$REMOTE_STAGE/setup-beamsig.sh" --uninstall
        tsh beams exec "$BEAM" -- rm -rf "$REMOTE_STAGE"
        echo "==> done"
        exit 0
    fi
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
TARBALL="$STAGE/beamsig.tar.gz"

echo "==> packing $HERE"
# Pack from an ALLOWLIST, not a list of excludes.
#
# `git ls-files --cached --others --exclude-standard` is tracked files plus
# untracked ones that .gitignore does not cover, so local uncommitted edits
# come along (which is what you want mid-development) while anything ignored
# stays behind. That matters: .gitignore deliberately hides the throwaway CA
# and user private keys that bin/negative-tests.sh mints under exp5/, the
# archived copies of the tbot identity file, and the 68M virtualenv. An exclude
# list had already shipped exp5/ to a Beam before this was changed.
if git -C "$HERE" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$HERE" ls-files --cached --others --exclude-standard -z \
        | tar -C "$HERE" --null -T - -czf "$TARBALL"
else
    echo "    note: not a git checkout, falling back to exclude list" >&2
    tar -C "$HERE" -czf "$TARBALL" \
        --exclude=./venv --exclude=./.git --exclude=./gen --exclude=./ca \
        --exclude=./run --exclude='./exp*' --exclude=./archive \
        --exclude=./inventory --exclude=./repos \
        --exclude='*.pyc' --exclude=__pycache__ .
fi
printf '    %s bytes\n' "$(wc -c <"$TARBALL")"

echo "==> copying to $BEAM:$REMOTE_STAGE"
tsh beams exec "$BEAM" -- mkdir -p "$REMOTE_STAGE"
tsh beams scp -q "$HERE/setup-beamsig.sh" "$BEAM:$REMOTE_STAGE/setup-beamsig.sh"
tsh beams scp -q "$TARBALL" "$BEAM:$REMOTE_STAGE/beamsig.tar.gz"

echo "==> running setup on $BEAM"
tsh beams exec "$BEAM" -- bash "$REMOTE_STAGE/setup-beamsig.sh" "$@"
