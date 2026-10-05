#!/usr/bin/env python3
"""A gpgsm-compatible shim so `git -c gpg.format=x509` can sign as a beam.

git drives the x509 program exactly like gpg:
    sign  : <prog> --status-fd=2 -bsau <keyid>        payload on stdin,
                                                      armored sig on stdout
    verify: <prog> --status-fd=1 --keyid-format=long --verify <sigfile> -
                                                      payload on stdin,
                                                      gpg status lines on fd N
git requires the signature to be armored with "-----BEGIN SIGNED MESSAGE-----"
(that is the marker in git's gpg_format table for x509).

IMPORTANT LIMITATION this shim works around: for gpg/x509, git does NOT pass
the commit timestamp to the signing program (`-Overify-time` is an
ssh-format-only feature). With a stock gpgsm, every beam commit would stop
verifying 61 minutes after it was made. This shim therefore parses the
committer date out of the commit object it is handed and passes it to
`openssl cms -verify -attime`, which is something gpgsm would never do.
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.environ.get("BEAMSIG_HOME") or
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_HOME = os.environ.get("BEAMSIG_HOME") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
CA = os.environ.get("BEAMSIG_X509_CA",
                    os.path.join(_HOME, "ca", "export-tls-user.txt"))
ARMOR_HEAD = b"-----BEGIN SIGNED MESSAGE-----"
ARMOR_FOOT = b"-----END SIGNED MESSAGE-----"


def armor(der: bytes) -> bytes:
    import base64
    b = base64.b64encode(der)
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return ARMOR_HEAD + b"\n" + b"\n".join(lines) + b"\n" + ARMOR_FOOT + b"\n"


def dearmor(data: bytes) -> bytes:
    import base64
    if ARMOR_HEAD not in data:
        return data
    body = data.split(ARMOR_HEAD, 1)[1].split(ARMOR_FOOT, 1)[0]
    return base64.b64decode(b"".join(body.split()))


def status_fd(argv):
    for a in argv:
        if a.startswith("--status-fd="):
            return int(a.split("=", 1)[1])
    return 2


def emit(fd, line):
    os.write(fd, b"[GNUPG:] " + line.encode() + b"\n")


def committer_time(payload: bytes):
    """Pull the committer timestamp out of a git commit object, if that is
    what we were handed."""
    head = payload.split(b"\n\n", 1)[0]
    for line in head.split(b"\n"):
        if line.startswith(b"committer "):
            try:
                return int(line.rsplit(b" ", 2)[1])
            except Exception:
                return None
    return None


def do_sign(argv):
    from beamsig import cmssign, identity as ident_mod
    from beamsig.hwagent import HardwareKeyAgent
    payload = sys.stdin.buffer.read()
    ident = ident_mod.load()
    hw = HardwareKeyAgent()
    der = cmssign.build_signed_data(payload, ident.x509_leaf_pem, hw,
                                    ident.hw_key, detached=True)
    sys.stdout.buffer.write(armor(der))
    sys.stdout.buffer.flush()
    emit(status_fd(argv), "SIG_CREATED D 0 8 00 0 0")
    return 0


def do_verify(argv):
    sfd = status_fd(argv)
    i = argv.index("--verify")
    sigfile = argv[i + 1]
    payload = sys.stdin.buffer.read()
    der = dearmor(open(sigfile, "rb").read())

    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "sig.der")
        cp = os.path.join(td, "content.bin")
        with open(sp, "wb") as f:
            f.write(der)
        with open(cp, "wb") as f:
            f.write(payload)
        cmd = ["openssl", "cms", "-verify", "-inform", "DER", "-in", sp,
               "-content", cp, "-binary", "-CAfile", CA, "-purpose", "any",
               "-out", "/dev/null"]
        ct = committer_time(payload)
        if ct:
            cmd += ["-attime", str(ct)]
        r = subprocess.run(cmd, capture_output=True)

    emit(sfd, "NEWSIG")
    if r.returncode == 0:
        # pull the beam identity out of the signer cert for the status line
        beam = "beam"
        try:
            from asn1crypto import cms
            ci = cms.ContentInfo.load(der)
            cert = ci["content"]["certificates"][0].chosen
            for rdn in cert["tbs_certificate"]["subject"].chosen:
                for at in rdn:
                    if at["type"].dotted == "1.3.9999.2.18":
                        beam = at["value"].native
        except Exception:
            pass
        emit(sfd, f"GOODSIG 0000000000000000 {beam}")
        emit(sfd, "TRUST_FULLY 0 shell")
        emit(sfd, "VALIDSIG 0000000000000000000000000000000000000000 "
                  f"- {ct or 0} 0 4 0 19 8 00 "
                  "0000000000000000000000000000000000000000")
        return 0
    emit(sfd, "BADSIG 0000000000000000 beam")
    sys.stderr.buffer.write(r.stderr)
    return 1


def main():
    argv = sys.argv[1:]
    if "--verify" in argv:
        return do_verify(argv)
    return do_sign(argv)


if __name__ == "__main__":
    sys.exit(main())
