#!/usr/bin/env python3
"""Experiment 2: dissect an SSHSIG blob. Does it embed the full certificate?"""
import datetime
import os
import sys

sys.path.insert(0, os.environ.get("BEAMSIG_HOME") or
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from beamsig import sshsig, sshcert  # noqa: E402


def ts(v):
    return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).isoformat()


for path in sys.argv[1:]:
    data = open(path, "rb").read()
    s = sshsig.parse(data)
    print("=" * 70)
    print(f"FILE               : {path}  ({len(data)} bytes armored, "
          f"{len(s.raw)} bytes raw)")
    print(f"  SSHSIG version   : {s.version}")
    print(f"  namespace        : {s.namespace!r}")
    print(f"  hash algorithm   : {s.hash_algorithm}")
    print(f"  reserved         : {s.reserved!r}")
    print(f"  publickey field  : {len(s.publickey)} bytes, type={s.publickey_type}")
    print(f"  inner sig alg    : {s.sig_algorithm}")
    print(f"  IS CERTIFICATE   : {s.is_certificate}")
    if s.is_certificate:
        c = sshcert.parse(s.publickey)
        print("  --- certificate recovered FROM THE SIGNATURE ALONE ---")
        print(f"    key id                 : {c.key_id}")
        print(f"    principals             : {c.valid_principals}")
        print(f"    valid                  : {ts(c.valid_after)} .. {ts(c.valid_before)}")
        print(f"    CA fingerprint         : {c.ca_fingerprint}")
        for k in sorted(c.extensions):
            v = c.extensions[k]
            try:
                v = v.decode()
            except Exception:
                v = v.hex()
            print(f"    ext {k:38s} = {v[:90]}")
    print()
