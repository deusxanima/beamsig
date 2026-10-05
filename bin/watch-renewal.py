#!/usr/bin/env python3
"""Watch the tbot identity file and archive every distinct version.

Answers: does the file change in place? does the KEY rotate, or only the cert?
"""
import datetime
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.environ.get("BEAMSIG_HOME") or
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from beamsig import identity as ident_mod, sshcert  # noqa: E402

_HOME = os.environ.get("BEAMSIG_HOME") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
ARCHIVE = os.path.join(_HOME, "archive")
LOG = os.path.join(_HOME, "logs", "renewal.jsonl")
PATH = ident_mod.DEFAULT_IDENTITY


def snapshot():
    st = os.stat(PATH)
    with open(PATH, "rb") as f:
        raw = f.read()
    ident = ident_mod.load(PATH)
    c = sshcert.parse_line(ident.ssh_cert_line)
    return raw, {
        "wall": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "file_mtime": datetime.datetime.fromtimestamp(
            st.st_mtime, datetime.timezone.utc).isoformat(),
        "file_inode": st.st_ino,
        "file_size": st.st_size,
        "pubkey_sha256": hashlib.sha256(ident.hw_key.public_key_der).hexdigest()
                         if ident.hw_key else None,
        "piv_serial": ident.hw_key.serial_number if ident.hw_key else None,
        "piv_slot": ident.hw_key.slot_key if ident.hw_key else None,
        "ssh_key_fp": c.key_fingerprint,
        "ssh_cert_valid_after": c.valid_after,
        "ssh_cert_valid_before": c.valid_before,
        "ssh_cert_sig_sha256": hashlib.sha256(c.signature).hexdigest(),
        "ssh_ca_fp": c.ca_fingerprint,
        "bot_instance_id": c.extensions.get("bot-instance-id@goteleport.com", b"").decode(),
        "delegation_session_id": c.extensions.get("delegation-session-id@goteleport.com", b"").decode(),
    }


def main():
    os.makedirs(ARCHIVE, exist_ok=True)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    seen = set()
    deadline = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 3600)
    n = 0
    while time.time() < deadline:
        try:
            raw, info = snapshot()
        except Exception as e:
            time.sleep(5)
            continue
        if info["file_sha256"] not in seen:
            seen.add(info["file_sha256"])
            name = f"{ARCHIVE}/identity-{n:03d}-{info['ssh_cert_valid_after']}"
            old = os.umask(0o077)
            try:
                with open(name, "wb") as f:
                    f.write(raw)
            finally:
                os.umask(old)
            info["archived_as"] = name
            with open(LOG, "a") as f:
                f.write(json.dumps(info) + "\n")
            print(json.dumps(info), flush=True)
            n += 1
        time.sleep(5)


if __name__ == "__main__":
    main()
