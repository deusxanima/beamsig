#!/usr/bin/env python3
"""Experiment 1: full inventory of the tbot identity file."""
import base64
import datetime
import json
import os
import sys

sys.path.insert(0, os.environ.get("BEAMSIG_HOME") or
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from beamsig import identity as ident_mod, sshcert  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402


def ts(v):
    if v >= 0xFFFFFFFFFFFFFFFF:
        return "forever"
    return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).isoformat()


def show_bytes(b):
    try:
        s = b.decode("utf-8")
        if s.isprintable():
            return s
    except Exception:
        pass
    return "<%d bytes> %s" % (len(b), b[:48].hex())


TELEPORT_OIDS = {
    "1.3.9999.1.1": "KubeUsers",
    "1.3.9999.1.2": "KubeGroups",
    "1.3.9999.1.3": "KubeCluster",
    "1.3.9999.1.4": "AppSessionID",
    "1.3.9999.1.7": "AppName",
    "1.3.9999.1.8": "AppPublicAddr",
    "1.3.9999.2.1": "TeleportCluster",
    "1.3.9999.2.7": "RouteToCluster(?)",
    "1.3.9999.2.9": "ClientIP",
    "1.3.9999.2.10": "AWSRoleARNs(?)",
    "1.3.9999.2.15": "Renewable/Impersonator(?)",
    "1.3.9999.2.18": "BotName",
    "1.3.9999.2.20": "BotInstanceID",
    "1.3.9999.2.30": "DelegationSessionID",
}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    ident = ident_mod.load(path)
    print("#" * 72)
    print("# IDENTITY FILE:", ident.path)
    print("#" * 72)

    print("\n== private key block ==")
    if ident.hw_key:
        hk = ident.hw_key
        print("  TYPE                : PIV hardware key REFERENCE (no key material)")
        print(f"  serial_number       : {hk.serial_number} (0x{hk.serial_number:08x})")
        print(f"  slot_key            : 0x{hk.slot_key:02X} -> enum {hk.slot_enum}")
        print(f"  touch_required      : {hk.touch_required}")
        print(f"  pin_required        : {hk.pin_required}")
        print(f"  pin_cache_ttl       : {hk.pin_cache_ttl}")
        pub = serialization.load_der_public_key(hk.public_key_der)
        print(f"  public_key          : {pub.curve.name} ({pub.key_size} bit)")
    elif ident.raw_private_key_pem:
        print("  TYPE                : REAL private key present (%d bytes PEM)"
              % len(ident.raw_private_key_pem))
    else:
        print("  TYPE                : none found")

    print("\n== SSH user certificate ==")
    c = sshcert.parse_line(ident.ssh_cert_line)
    print(f"  keytype             : {c.keytype}")
    print(f"  serial              : {c.serial}")
    print(f"  type                : {c.cert_type} ({sshcert.CERT_TYPE.get(c.cert_type)})")
    print(f"  key id              : {c.key_id}     <-- OWNER (impersonation)")
    print(f"  principals          : {c.valid_principals}")
    print(f"  valid after         : {c.valid_after} {ts(c.valid_after)}")
    print(f"  valid before        : {c.valid_before} {ts(c.valid_before)}")
    print(f"  lifetime            : {c.valid_before - c.valid_after}s")
    print(f"  key fingerprint     : {c.key_fingerprint}")
    print(f"  CA fingerprint      : {c.ca_fingerprint}")
    print(f"  critical options    : {c.critical_options or '{}'}")
    print("  extensions:")
    for k in sorted(c.extensions):
        print(f"    {k:42s} = {show_bytes(c.extensions[k])}")

    print("\n== X.509 leaf ==")
    leaf = x509.load_pem_x509_certificate(ident.x509_leaf_pem)
    print(f"  subject             : {leaf.subject.rfc4514_string()[:200]}")
    print(f"  issuer              : {leaf.issuer.rfc4514_string()}")
    print(f"  serial              : {leaf.serial_number}")
    print(f"  not before          : {leaf.not_valid_before_utc.isoformat()}")
    print(f"  not after           : {leaf.not_valid_after_utc.isoformat()}")
    print(f"  sig alg             : {leaf.signature_algorithm_oid._name}")
    print(f"  fingerprint sha256  : {leaf.fingerprint(hashes.SHA256()).hex()}")
    print("  subject RDNs (incl. Teleport custom OIDs):")
    for rdn in leaf.subject.rdns:
        for at in rdn:
            oid = at.oid.dotted_string
            name = TELEPORT_OIDS.get(oid, at.oid._name or "")
            v = at.value
            if isinstance(v, bytes):
                v = v.hex()
            v = str(v)
            if len(v) > 150:
                v = v[:150] + "..."
            print(f"    {oid:18s} {name:22s} = {v}")
    print("  extensions:")
    for ext in leaf.extensions:
        print(f"    {ext.oid.dotted_string:22s} {ext.oid._name}")

    print("\n== X.509 CA chain from identity file ==")
    for i, pem in enumerate(ident.x509_chain_pem):
        ca = x509.load_pem_x509_certificate(pem)
        print(f"  [{i}] subject={ca.subject.rfc4514_string()}")
        print(f"      issuer ={ca.issuer.rfc4514_string()}")
        print(f"      serial ={ca.serial_number}")
        print(f"      valid  ={ca.not_valid_before_utc.date()} .. {ca.not_valid_after_utc.date()}")
        print(f"      sha256 ={ca.fingerprint(hashes.SHA256()).hex()}")
        try:
            bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
            print(f"      CA     ={bc.ca}")
        except Exception:
            pass

    print("\n== @cert-authority lines (SSH host CA, known_hosts format) ==")
    for line in ident.known_hosts_ca:
        print("  " + line[:160])

    print("\n== does the leaf public key match the SSH cert public key? ==")
    leaf_pub_der = leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    hw_der = ident.hw_key.public_key_der if ident.hw_key else b""
    print(f"  x509 leaf pub == PIV ref pub : {leaf_pub_der == hw_der}")
    # SSH cert point vs x509 point
    from cryptography.hazmat.primitives.asymmetric import ec
    pub = serialization.load_der_public_key(hw_der) if hw_der else None
    if pub:
        pt = pub.public_bytes(serialization.Encoding.X962,
                              serialization.PublicFormat.UncompressedPoint)
        from beamsig.wire import Reader
        rr = Reader(c.pubkey_blob)
        rr.string(); rr.string()
        ssh_pt = rr.string()
        print(f"  ssh cert pub   == PIV ref pub : {ssh_pt == pt}")


if __name__ == "__main__":
    main()
