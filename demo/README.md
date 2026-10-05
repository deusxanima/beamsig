# Demo recordings

Two short loops, as asciinema v2 casts:

| cast | shows |
|---|---|
| `beamsig-install.cast` | `./main.sh vapor-jet`, then `tsh beams ssh`, then proof the git config landed |
| `beamsig-commit.cast` | a signed commit, `git log` showing the beam, and a failed verification |

Regenerate with `./record-demo.py`. Preview in a terminal with
`./record-demo.py --play install` (or `commit`).

The transcripts are **reconstructed, not captured**. The text is copied from
real runs against beams `clever-nebula` and `vapor-jet`, but a live recording
spends about three minutes on apt and pip output that nobody wants to watch in
a loop. Timings are chosen for readability. If you change the real output,
re-sync `record-demo.py` — it has already drifted once.

## Turning them into GIFs

```bash
asciinema play beamsig-install.cast                       # watch it
agg --theme asciinema beamsig-install.cast beamsig-install.gif
agg --theme asciinema beamsig-commit.cast  beamsig-commit.gif
```

[`agg`](https://github.com/asciinema/agg) is the asciinema GIF generator.
`svg-term` works too if you want SVG. The casts are 104x28; the longest line is
the `Good "git" signature ...` header, which is split across two lines in the
recording so it does not wrap at that width.

`./record-demo.py --ascii` uses `$` instead of the `❯` prompt glyph, for fonts
that lack it.
