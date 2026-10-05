"""Parse a Teleport tbot identity file into its components.

The tbot identity file is a concatenation of PEM-ish blocks and
OpenSSH one-liners:

  -----BEGIN PIV YUBIKEY PRIVATE KEY-----   (JSON hardware key reference, NOT a key)
  ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA...   (SSH user cert)
  -----BEGIN CERTIFICATE-----               (x509 leaf, then CA chain)
  @cert-authority <hosts> ecdsa-... type=host  (SSH host CA, known_hosts format)
"""
import base64
import json
import os
import re
from dataclasses import dataclass, field

DEFAULT_IDENTITY = os.environ.get("TELEPORT_IDENTITY_FILE",
                                  "/var/run/tbot/identity/identity")
DEFAULT_AGENT_DIR = os.environ.get("TELEPORT_KEY_AGENT_DIR",
                                   "/var/run/tbot/identity")

PIV_SLOT_ENUM = {0x9A: 1, 0x9C: 2, 0x9D: 3, 0x9E: 4}


@dataclass
class HardwareKeyRef:
    serial_number: int
    slot_key: int             # raw PIV slot byte, e.g. 0x9A
    public_key_der: bytes
    touch_required: bool = False
    pin_required: bool = False
    pin_cache_ttl: int = 0

    @property
    def slot_enum(self) -> int:
        return PIV_SLOT_ENUM[self.slot_key]


@dataclass
class Identity:
    path: str
    ssh_cert_line: bytes = b""          # "ecdsa-...-cert-v01@openssh.com AAAA..."
    x509_leaf_pem: bytes = b""
    x509_chain_pem: list = field(default_factory=list)
    known_hosts_ca: list = field(default_factory=list)
    hw_key: HardwareKeyRef = None
    raw_private_key_pem: bytes = b""    # only set if a real key is present

    @property
    def ssh_cert_blob(self) -> bytes:
        parts = self.ssh_cert_line.split()
        return base64.b64decode(parts[1])


def load(path: str = None) -> Identity:
    path = path or DEFAULT_IDENTITY
    with open(path, "r") as f:
        text = f.read()
    ident = Identity(path=path)

    # -- SSH certificate line
    for line in text.splitlines():
        if re.match(r"^(ssh-|ecdsa-|rsa-)\S*-cert-v01@openssh\.com\s+\S+", line):
            ident.ssh_cert_line = line.strip().encode()
        elif line.startswith("@cert-authority "):
            ident.known_hosts_ca.append(line.strip())

    # -- X.509 certs, leaf first
    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if certs:
        ident.x509_leaf_pem = (certs[0] + "\n").encode()
        ident.x509_chain_pem = [(c + "\n").encode() for c in certs[1:]]

    # -- Private key block
    m = re.search(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----(.*?)-----END \1-----",
                  text, re.S)
    if m:
        label, body = m.group(1), m.group(2)
        if "PIV" in label:
            ref = json.loads(base64.b64decode("".join(body.split())))
            pol = ref.get("policy") or {}
            ident.hw_key = HardwareKeyRef(
                serial_number=ref["serial_number"],
                slot_key=ref["slot_key"],
                public_key_der=base64.b64decode(ref["public_key"]),
                touch_required=bool(pol.get("TouchRequired")),
                pin_required=bool(pol.get("PINRequired")),
                pin_cache_ttl=int(ref.get("pin_cache_ttl") or 0),
            )
        else:
            ident.raw_private_key_pem = m.group(0).encode()
    return ident
