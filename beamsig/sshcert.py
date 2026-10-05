"""Parse OpenSSH certificates (RFC-ish: PROTOCOL.certkeys)."""
import base64
import hashlib
from dataclasses import dataclass, field

from .wire import Reader, Writer

CERT_TYPE = {1: "user", 2: "host"}


@dataclass
class SSHCert:
    keytype: str
    nonce: bytes
    pubkey_blob: bytes            # bare public key blob (type,curve,point)
    serial: int
    cert_type: int
    key_id: str
    valid_principals: list
    valid_after: int
    valid_before: int
    critical_options: dict = field(default_factory=dict)
    extensions: dict = field(default_factory=dict)
    reserved: bytes = b""
    signature_key: bytes = b""    # CA public key blob
    signature: bytes = b""
    signed_bytes: bytes = b""     # everything the CA signed over
    blob: bytes = b""

    @property
    def ca_fingerprint(self) -> str:
        return "SHA256:" + base64.b64encode(
            hashlib.sha256(self.signature_key).digest()).decode().rstrip("=")

    @property
    def key_fingerprint(self) -> str:
        return "SHA256:" + base64.b64encode(
            hashlib.sha256(self.pubkey_blob).digest()).decode().rstrip("=")


def _kv_pairs(buf: bytes) -> dict:
    """critical options / extensions are a sequence of (name, data) strings."""
    out = {}
    r = Reader(buf)
    while not r.eof():
        name = r.cstring()
        data = r.string()
        # Many Teleport extensions wrap their payload in a second string layer.
        val = data
        if data:
            try:
                inner = Reader(data)
                s = inner.string()
                if inner.eof():
                    val = s
            except Exception:
                pass
        out[name] = val
    return out


def parse(blob: bytes) -> SSHCert:
    r = Reader(blob)
    keytype = r.cstring()
    if "-cert-v01@openssh.com" not in keytype:
        raise ValueError(f"not an OpenSSH certificate: {keytype}")
    nonce = r.string()
    if keytype.startswith("ecdsa-sha2-"):
        curve = r.string()
        point = r.string()
        pubkey_blob = (Writer()
                       .string(keytype.replace("-cert-v01@openssh.com", ""))
                       .string(curve).string(point).bytes())
    elif keytype.startswith("ssh-ed25519"):
        pk = r.string()
        pubkey_blob = Writer().string("ssh-ed25519").string(pk).bytes()
    elif keytype.startswith("ssh-rsa"):
        e = r.string()
        n = r.string()
        pubkey_blob = Writer().string("ssh-rsa").string(e).string(n).bytes()
    else:
        raise ValueError(f"unsupported cert key type {keytype}")
    serial = r.u64()
    cert_type = r.u32()
    key_id = r.cstring()
    principals = Reader(r.string())
    valid_principals = []
    while not principals.eof():
        valid_principals.append(principals.cstring())
    valid_after = r.u64()
    valid_before = r.u64()
    crit = _kv_pairs(r.string())
    exts = _kv_pairs(r.string())
    reserved = r.string()
    sig_key = r.string()
    signed_len = r.i            # everything up to (not including) the signature
    signature = r.string()
    return SSHCert(
        keytype=keytype, nonce=nonce, pubkey_blob=pubkey_blob, serial=serial,
        cert_type=cert_type, key_id=key_id, valid_principals=valid_principals,
        valid_after=valid_after, valid_before=valid_before,
        critical_options=crit, extensions=exts, reserved=reserved,
        signature_key=sig_key, signature=signature,
        signed_bytes=blob[:signed_len], blob=blob,
    )


def parse_line(line) -> SSHCert:
    if isinstance(line, bytes):
        line = line.decode()
    parts = line.split()
    for p in parts:
        if p.startswith("AAAA"):
            return parse(base64.b64decode(p))
    raise ValueError("no base64 blob found in line")
