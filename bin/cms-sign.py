#!/usr/bin/env python3
"""Sign an artifact as this beam, producing CMS SignedData via the hw agent."""
import argparse
import datetime
import os
import sys

sys.path.insert(0, os.environ.get("BEAMSIG_HOME") or
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from beamsig import cmssign, identity as ident_mod  # noqa: E402
from beamsig.hwagent import HardwareKeyAgent  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument("infile")
p.add_argument("-o", "--out", required=True)
p.add_argument("--detached", action="store_true")
p.add_argument("--pem", action="store_true")
p.add_argument("--signing-time", action="store_true",
               help="include a (self-reported) signingTime attribute")
a = p.parse_args()

ident = ident_mod.load()
if not ident.hw_key:
    sys.exit("no hardware key reference in identity")
hw = HardwareKeyAgent()

with open(a.infile, "rb") as f:
    payload = f.read()

st = datetime.datetime.now(datetime.timezone.utc) if a.signing_time else None
der = cmssign.build_signed_data(payload, ident.x509_leaf_pem, hw, ident.hw_key,
                                detached=a.detached, signing_time=st)
out = cmssign.to_pem(der) if a.pem else der
with open(a.out, "wb") as f:
    f.write(out)
print(f"wrote {a.out} ({len(out)} bytes, "
      f"{'detached' if a.detached else 'attached'}, "
      f"{'PEM' if a.pem else 'DER'})")
