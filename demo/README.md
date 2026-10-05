# Demo recordings

Two short loops, as asciinema v2 casts:

| cast / gif | terminal | length | size | shows |
|---|---|---|---|---|
| `beamsig-install` | 104x28 | 25s | 416 KB | `./main.sh vapor-jet`, `tsh beams ssh`, and three commands proving the config landed |
| `beamsig-install-short` | 80x16 | 15s | 83 KB | the same story, abridged — larger text, one proof command |
| `beamsig-commit` | 104x28 | 21s | 259 KB | a signed commit, `git log` showing the beam, `%G?`/`%GS`, and a verification that correctly fails |

Two install variants on purpose. The full one is faithful to a real run. The
short one trades fidelity for legibility: the four `== ... ==` setup stages
collapse to one line, the CA path and fingerprint go, the beam UUID is elided
after its first component, and two of the three proof commands are cut. Nothing
misleading is added — every line still appears in a real run — but if you are
quoting output rather than showing a loop, use the full one. The payoff is a
80x16 terminal instead of 104x28, so a similar pixel width carries much larger
text, which is what matters embedded in a README or a slide.

Regenerate with `./record-demo.py`. Preview in a terminal with
`./record-demo.py --play install-short` (or `install`, `commit`).

The transcripts are **reconstructed, not captured**. The text is copied from
real runs against beams `clever-nebula` and `vapor-jet`, but a live recording
spends about three minutes on apt and pip output that nobody wants to watch in
a loop. Timings are chosen for readability. If you change the real output,
re-sync `record-demo.py` — it has already drifted once.

## Turning them into GIFs

```bash
./make-gifs.sh                        # regenerate casts and render all three
asciinema play beamsig-install.cast   # or just watch one
```

`make-gifs.sh` documents the `agg` and font install at the top of the file. On a
bare Beam image there are **no fonts at all** and `agg` fails; JetBrains Mono
is worth installing because it is `agg`'s first default family and it has the
U+276F chevron used in the prompt.

[`agg`](https://github.com/asciinema/agg) is the asciinema GIF generator.
`svg-term` works too if you want SVG. In the full-size casts the longest line
is the `Good "git" signature ...` header, which is split across two lines in
the recording so it does not wrap at 104 columns.

`./record-demo.py --ascii` uses `$` instead of the `❯` prompt glyph, for fonts
that lack it.
