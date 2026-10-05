"""Verify SSH-format signatures (ECDSA / Ed25519 / RSA) using `cryptography`."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .wire import Reader

CURVES = {
    "nistp256": (ec.SECP256R1, hashes.SHA256),
    "nistp384": (ec.SECP384R1, hashes.SHA384),
    "nistp521": (ec.SECP521R1, hashes.SHA512),
}

RSA_HASHES = {
    "ssh-rsa": hashes.SHA1,
    "rsa-sha2-256": hashes.SHA256,
    "rsa-sha2-512": hashes.SHA512,
}


def load_ssh_pubkey(blob: bytes):
    """Load a bare SSH public key blob into a `cryptography` public key."""
    r = Reader(blob)
    kt = r.cstring()
    if kt.startswith("ecdsa-sha2-"):
        curve_name = r.cstring()
        point = r.string()
        curve_cls, _ = CURVES[curve_name]
        return kt, ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), point)
    if kt == "ssh-ed25519":
        return kt, ed25519.Ed25519PublicKey.from_public_bytes(r.string())
    if kt == "ssh-rsa":
        e = r.mpint()
        n = r.mpint()
        return kt, rsa.RSAPublicNumbers(e, n).public_key()
    raise ValueError(f"unsupported SSH key type {kt}")


def verify(pubkey_blob: bytes, sig_blob: bytes, message: bytes) -> str:
    """Verify an SSH signature blob over `message`.

    Returns the signature algorithm name, or raises InvalidSignature/ValueError.
    """
    kt, key = load_ssh_pubkey(pubkey_blob)
    r = Reader(sig_blob)
    alg = r.cstring()
    sigdata = r.string()

    if isinstance(key, ec.EllipticCurvePublicKey):
        if not alg.startswith("ecdsa-sha2-"):
            raise ValueError(f"algorithm {alg} does not match an ECDSA key")
        if alg != kt:
            raise ValueError(f"signature alg {alg} != key type {kt}")
        curve_name = alg.split("ecdsa-sha2-")[1]
        _, hash_cls = CURVES[curve_name]
        ir = Reader(sigdata)
        rr, ss = ir.mpint(), ir.mpint()
        if not ir.eof():
            raise ValueError("trailing bytes in ECDSA signature")
        key.verify(encode_dss_signature(rr, ss), message, ec.ECDSA(hash_cls()))
        return alg

    if isinstance(key, ed25519.Ed25519PublicKey):
        if alg != "ssh-ed25519":
            raise ValueError(f"signature alg {alg} != ssh-ed25519")
        key.verify(sigdata, message)
        return alg

    if isinstance(key, rsa.RSAPublicKey):
        if alg not in RSA_HASHES:
            raise ValueError(f"unsupported RSA signature alg {alg}")
        key.verify(sigdata, message, padding.PKCS1v15(), RSA_HASHES[alg]())
        return alg

    raise ValueError("unsupported key")
