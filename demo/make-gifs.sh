#!/usr/bin/env bash
# Regenerate the casts and render them to GIFs.
#
# Needs `agg` (the asciinema GIF generator) and a monospace font. On a bare
# Beam image there are no fonts at all and agg fails, so install one:
#
#   sudo apt-get install -y fontconfig fonts-jetbrains-mono
#   curl -fsSL -o /tmp/agg \
#     https://github.com/asciinema/agg/releases/download/v1.9.0/agg-x86_64-unknown-linux-musl
#   chmod +x /tmp/agg && sudo mv /tmp/agg /usr/local/bin/agg
#
# JetBrains Mono is worth the 2MB: it is agg's first default family and it has
# the U+276F chevron used in the prompt. DejaVu Sans Mono also works.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

command -v agg >/dev/null || {
    echo "agg is not installed; see the header of this script" >&2
    exit 1
}
if ! fc-list 2>/dev/null | grep -qi mono; then
    echo "no monospace font found; agg will fail. See the header." >&2
    exit 1
fi

./record-demo.py

# The abridged install uses an 80x16 terminal, so it can carry a larger font
# in a similar pixel width.
font_for() { case "$1" in install-short) echo 20 ;; *) echo 16 ;; esac; }

for name in install install-short commit; do
    # --idle-time-limit trims the deliberate pauses so a loop does not stall;
    # --fps-cap 20 roughly halves the frame count at no visible cost.
    agg --theme asciinema \
        --font-size "$(font_for "$name")" \
        --line-height 1.4 \
        --fps-cap 20 \
        --idle-time-limit 2 \
        --last-frame-duration 2 \
        "beamsig-$name.cast" "beamsig-$name.gif" >/dev/null 2>&1
    printf '%-30s %4s KB\n' "beamsig-$name.gif" \
        "$(( $(stat -c%s "beamsig-$name.gif") / 1024 ))"
done
