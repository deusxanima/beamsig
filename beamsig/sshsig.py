"""SSHSIG (OpenSSH signature) parse / verify.

Format (PROTOCOL.sshsig), armored as PEM "SSH SIGNATURE":

    byte[6]  MAGIC_PREAMBLE = "SSHSIG"
    uint32   SIG_VERSION    = 1
    string   publickey          <-- full certificate blob when signing with a cert
    string   namespace
    string   reserved
    string   hash_algorithm
    string   signature

The signature is computed over this "signed data" blob:

    byte[6]  MAGIC_PREAMBLE
    string   namespace
    string   reserved
    string   hash_algorithm
    string   H(message)
"""
import base64
import hashlib
import re
from dataclasses import dataclass

from .wire import Reader, Writer

MAGIC = b"SSHSIG"
PEM_RE = re.compile(
    rb"-----BEGIN SSH SIGNATURE-----(.*?)-----END SSH SIGNATURE-----", re.S)

HASHES = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}


@dataclass
class SSHSig:
    version: int
    publickey: bytes       # may be a bare key blob OR a full certificate blob
    namespace: str
    reserved: bytes
    hash_algorithm: str
    signature: bytes       # inner SSH signature blob (string alg, string sigdata)
    raw: bytes

    @property
    def is_certificate(self) -> bool:
        try:
            return b"-cert-v01@openssh.com" in Reader(self.publickey).string()
        except Exception:
            return False

    @property
    def publickey_type(self) -> str:
        return Reader(self.publickey).string().decode()

    @property
    def sig_algorithm(self) -> str:
        return Reader(self.signature).string().decode()


def dearmor(data: bytes) -> bytes:
    m = PEM_RE.search(data)
    if not m:
        raise ValueError("no SSH SIGNATURE PEM block found")
    return base64.b64decode(re.sub(rb"\s+", b"", m.group(1)))


def armor(blob: bytes) -> bytes:
    b = base64.b64encode(blob)
    lines = [b[i:i + 70] for i in range(0, len(b), 70)]
    return (b"-----BEGIN SSH SIGNATURE-----\n" + b"\n".join(lines) +
            b"\n-----END SSH SIGNATURE-----\n")


def parse(data: bytes) -> SSHSig:
    blob = dearmor(data) if b"BEGIN SSH SIGNATURE" in data else data
    if blob[:6] != MAGIC:
        raise ValueError("bad SSHSIG magic")
    r = Reader(blob[6:])
    version = r.u32()
    pk = r.string()
    ns = r.cstring()
    reserved = r.string()
    halg = r.cstring()
    sig = r.string()
    return SSHSig(version=version, publickey=pk, namespace=ns, reserved=reserved,
                  hash_algorithm=halg, signature=sig, raw=blob)


def signed_data(namespace: str, hash_algorithm: str, message: bytes,
                reserved: bytes = b"") -> bytes:
    h = HASHES[hash_algorithm](message).digest()
    return (MAGIC + Writer().string(namespace).string(reserved)
            .string(hash_algorithm).string(h).bytes())


def build(publickey_blob: bytes, namespace: str, hash_algorithm: str,
          signature_blob: bytes, reserved: bytes = b"") -> bytes:
    return (MAGIC + Writer().u32(1).string(publickey_blob).string(namespace)
            .string(reserved).string(hash_algorithm).string(signature_blob).bytes())
