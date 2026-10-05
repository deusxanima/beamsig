"""Extract the signed payload and SSHSIG blob from a signed git commit/tag.

Git stores the signature in a `gpgsig` header (continuation lines are prefixed
with a single space). The signed payload is the object text with that header
and its continuation lines removed, everything else byte-for-byte preserved.
"""
import subprocess

SIG_HEADERS = (b"gpgsig", b"gpgsig-sha256")


def raw_object(ref: str, repo: str = ".", kind: str = "commit") -> bytes:
    return subprocess.check_output(
        ["git", "-C", repo, "cat-file", kind, ref])


def split_signature(obj: bytes):
    """Return (payload_without_sig, signature_bytes)."""
    # Headers end at the first blank line.
    head_end = obj.find(b"\n\n")
    if head_end == -1:
        return obj, b""
    head, body = obj[:head_end + 1], obj[head_end + 1:]

    out_lines = []
    sig_lines = []
    in_sig = False
    for line in head.split(b"\n"):
        if in_sig:
            if line.startswith(b" "):
                sig_lines.append(line[1:])
                continue
            in_sig = False
        key = line.split(b" ", 1)[0]
        if key in SIG_HEADERS:
            in_sig = True
            rest = line.split(b" ", 1)[1] if b" " in line else b""
            sig_lines.append(rest)
            continue
        out_lines.append(line)
    payload = b"\n".join(out_lines) + body
    return payload, b"\n".join(sig_lines)


def commit_metadata(obj: bytes) -> dict:
    """Pull author/committer identity and timestamps out of a commit object."""
    meta = {}
    head_end = obj.find(b"\n\n")
    head = obj[:head_end] if head_end != -1 else obj
    for line in head.split(b"\n"):
        if line.startswith(b"author ") or line.startswith(b"committer "):
            k, v = line.split(b" ", 1)
            v = v.decode("utf-8", "replace")
            # "Name <email> <unixtime> <tzoffset>"
            parts = v.rsplit(" ", 2)
            meta[k.decode()] = {
                "identity": parts[0],
                "timestamp": int(parts[1]),
                "tz": parts[2],
            }
        elif line.startswith(b"tree "):
            meta["tree"] = line.split(b" ", 1)[1].decode()
    return meta
