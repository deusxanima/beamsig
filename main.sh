#!/usr/bin/env bash
# Run on your machine after logging in to your Beams cluster with tsh.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./main.sh [beam-name-or-uuid] [options]

Creates a Beam by default, then installs and configures beamsig on it.
Pass an existing Beam name or UUID to set up that Beam instead.

Setup makes every git repository on the Beam sign its commits with the Beam's
own Teleport identity, and makes `git log` report which Beam signed. A
signature embeds the whole Teleport certificate, so it can be verified later
against the cluster's SSH user CA alone, after the Beam is gone.

The Beam is not assumed to have git credentials and clones nothing: this packs
the checkout, copies it across with `tsh beams scp`, and runs the setup over
`tsh beams exec`.

Options:
  --no-autosign   Install, but do not sign commits by default.
  --no-showsig    Install, but do not show signatures in git log.
  --uninstall     Remove beamsig from the Beam. Requires a Beam argument.
  -h, --help      Show this help and exit.

Examples:
  ./main.sh                       # create a new Beam, then set up beamsig
  ./main.sh daring-lab            # set up beamsig on an existing Beam
  ./main.sh daring-lab --uninstall
EOF
}

beam=''
setup_args=()
uninstall=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        --no-autosign | --no-showsig) setup_args+=("$1") ;;
        --uninstall) uninstall=true ;;
        -*)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -n $beam ]]; then
                echo 'Expected at most one Beam name or UUID.' >&2
                usage >&2
                exit 2
            fi
            beam=$1
            ;;
    esac
    shift
done

command -v tsh >/dev/null || { echo 'Install tsh and log in to your Beams cluster first.' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
remote_home=/home/beams

test -f "$script_dir/setup-beamsig.sh" || {
    echo 'setup-beamsig.sh is missing; run this from the beamsig checkout.' >&2
    exit 1
}

if [[ $uninstall == true && -z $beam ]]; then
    echo 'Pass the Beam to uninstall from; refusing to create one just to tear it down.' >&2
    exit 2
fi

if [[ -z $beam ]]; then
    command -v jq >/dev/null || { echo 'Install jq to parse the new Beam ID.' >&2; exit 1; }
    echo 'Creating a new Beam...'
    beam=$(tsh beams add --no-console --format=json | jq -er '.id | select(type == "string" and length > 0)')
fi
if [[ ! $beam =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]]; then
    echo 'Expected a Beam name or UUID.' >&2
    exit 2
fi

printf 'Setting up Beam: %s\n' "$beam"
echo 'Waiting for SSH to become ready...'
# New Beams can be listed before their SSH node has registered.
for attempt in {1..15}; do
    if ssh_error=$(tsh beams exec "$beam" -- true 2>&1); then
        break
    fi
    if [[ $attempt -eq 15 ]]; then
        printf '%s\n' "$ssh_error" >&2
        echo "Beam $beam is not reachable; retry with: $0 $beam" >&2
        exit 1
    fi
    printf 'Still waiting for SSH (%s/15)...\n' "$attempt"
    sleep 2
done
echo 'SSH is ready.'

if [[ $uninstall == true ]]; then
    echo 'Removing beamsig from the Beam...'
    # Note: tsh beams exec re-splits its arguments, so quoted shell one-liners
    # such as `bash -c '...'` arrive mangled. Only ever invoke a script by path,
    # and branch here rather than on the Beam. The copy inside the install tree
    # is the fallback: the installer that was copied to the home directory may
    # have been tidied away, or put somewhere else by an older version.
    tsh beams exec "$beam" -- bash "$remote_home/setup-beamsig.sh" --uninstall ||
        tsh beams exec "$beam" -- bash "$remote_home/.beamsig/setup-beamsig.sh" --uninstall ||
        {
            echo 'Could not find setup-beamsig.sh on the Beam; nothing to uninstall.' >&2
            exit 1
        }
    tsh beams exec "$beam" -- rm -f "$remote_home/setup-beamsig.sh" "$remote_home/beamsig.tar.gz"
    printf '\nbeamsig is removed from %s.\n' "$beam"
    exit 0
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
tarball=$stage/beamsig.tar.gz

echo 'Packing the checkout...'
# Pack from an allowlist, not a list of excludes. `git ls-files --cached
# --others --exclude-standard` is tracked files plus untracked ones that
# .gitignore does not cover, so local uncommitted edits come along while
# anything ignored stays behind. That matters: .gitignore deliberately hides
# the throwaway CA and user private keys that bin/negative-tests.sh mints under
# exp5/, the archived copies of the tbot identity file, and the 68M virtualenv,
# which is rebuilt on the Beam. An exclude list had already shipped exp5/ to a
# Beam before this was changed.
if git -C "$script_dir" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$script_dir" ls-files --cached --others --exclude-standard -z |
        tar -C "$script_dir" --null -T - -czf "$tarball"
else
    echo 'Not a git checkout; falling back to an exclude list.' >&2
    tar -C "$script_dir" -czf "$tarball" \
        --exclude=./venv --exclude=./.git --exclude=./gen --exclude=./ca \
        --exclude=./run --exclude='./exp*' --exclude=./archive \
        --exclude=./inventory --exclude=./repos \
        --exclude='*.pyc' --exclude=__pycache__ .
fi
printf 'Packed %s bytes.\n' "$(wc -c <"$tarball")"

echo 'Copying the installer and the beamsig tree...'
tsh beams scp "$script_dir/setup-beamsig.sh" "$beam:$remote_home/setup-beamsig.sh"
tsh beams scp "$tarball" "$beam:$remote_home/beamsig.tar.gz"

echo 'Running beamsig setup on the Beam...'
tsh beams exec "$beam" -- bash "$remote_home/setup-beamsig.sh" ${setup_args[@]+"${setup_args[@]}"}

printf '\nbeamsig is ready. Connect with: tsh beams ssh %s\n' "$beam"
printf 'Then: git commit, and git log will show the Beam that signed.\n'
printf 'Remove it with: %s %s --uninstall\n' "$0" "$beam"
