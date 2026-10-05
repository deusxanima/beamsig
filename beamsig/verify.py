"""Beam-specific verification of SSHSIG signatures made with a Teleport bot cert.

What this adds over `ssh-keygen -Y verify`:

  * requires the signature to carry a *certificate* (not a bare key)
  * verifies the certificate against a pinned Teleport SSH user CA
  * requires a `bot-name@goteleport.com` extension matching `beam-<uuid>`
  * checks a caller-supplied claimed time against the certificate window
  * surfaces bot instance id / delegation session id / roles / owner

`ssh-keygen -Y verify` cannot do any of the beam-specific parts: it only
matches certificate *principals*, which on a beam are the generic Unix logins
`root` / `beams` and are shared by every user cert in the cluster.
"""
import base64
import datetime
import re
import urllib.request
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature

from . import sshcert, sshcrypto, sshsig
from .wire import Reader

BOT_NAME_EXT = "bot-name@goteleport.com"
BOT_INSTANCE_EXT = "bot-instance-id@goteleport.com"
DELEGATION_EXT = "delegation-session-id@goteleport.com"
ROLES_EXT = "teleport-roles"
TRAITS_EXT = "teleport-traits"
ROUTE_EXT = "teleport-route-to-cluster"
LOGIN_IP_EXT = "login-ip"

BEAM_BOT_RE = re.compile(
    r"^beam-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")

CERT_TYPE_USER = 1


class VerifyError(Exception):
    """Verification failed. The message says exactly which check failed."""


@dataclass
class Attestation:
    ok: bool = False
    namespace: str = ""
    payload_sha256: str = ""
    # beam identity
    beam_id: str = ""
    bot_name: str = ""
    bot_instance_id: str = ""
    delegation_session_id: str = ""
    owner: str = ""              # cert Key ID = the impersonated human
    roles: list = field(default_factory=list)
    principals: list = field(default_factory=list)
    login_ip: str = ""
    cluster: str = ""
    # crypto
    signing_key_fp: str = ""
    ca_fp: str = ""
    cert_serial: int = 0
    sig_algorithm: str = ""
    # time
    valid_after: int = 0
    valid_before: int = 0
    claimed_time: int = None
    claimed_time_source: str = ""
    warnings: list = field(default_factory=list)


def _iso(v):
    return datetime.datetime.fromtimestamp(v, datetime.timezone.utc).isoformat()


def load_ca_blobs(source: str) -> list:
    """Load Teleport SSH user CA public key blobs.

    `source` is either a path to a pinned file, or an https URL to
    /webapi/auth/export?type=user. Accepts both the raw Teleport export format
    (`cert-authority <type> <b64> ...`) and allowed_signers/known_hosts lines.
    """
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=20) as r:
            text = r.read().decode()
    else:
        with open(source) as f:
            text = f.read()
    blobs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for tok in line.split():
            if tok.startswith("AAAA"):
                try:
                    blob = base64.b64decode(tok)
                    Reader(blob).string()
                    blobs.append(blob)
                except Exception:
                    pass
                break
    if not blobs:
        raise VerifyError(f"no SSH CA public keys found in {source}")
    return blobs


def fp(blob: bytes) -> str:
    import hashlib
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")


def verify_sshsig(sig_bytes: bytes, payload: bytes, ca_blobs: list,
                  namespace: str = "git", claimed_time: int = None,
                  claimed_time_source: str = "caller",
                  require_beam: bool = True,
                  expect_beam_id: str = None) -> Attestation:
    import hashlib

    att = Attestation()

    # ---- 1. parse the SSHSIG envelope
    try:
        s = sshsig.parse(sig_bytes)
    except Exception as e:
        raise VerifyError(f"malformed SSHSIG: {e}")
    if s.version != 1:
        raise VerifyError(f"unsupported SSHSIG version {s.version}")
    att.namespace = s.namespace
    att.payload_sha256 = hashlib.sha256(payload).hexdigest()
    if namespace is not None and s.namespace != namespace:
        raise VerifyError(
            f"namespace mismatch: signature is for {s.namespace!r}, "
            f"expected {namespace!r}")
    if s.hash_algorithm not in sshsig.HASHES:
        raise VerifyError(f"unsupported hash algorithm {s.hash_algorithm}")

    # ---- 2. the signature MUST carry a certificate, else there is no identity
    if not s.is_certificate:
        raise VerifyError(
            "signature carries a bare public key, not a certificate; "
            "no beam identity can be established (re-sign using the "
            "Teleport SSH certificate)")
    cert = sshcert.parse(s.publickey)

    # ---- 3. the certificate must chain to a pinned Teleport user CA
    ca_ok = False
    for ca in ca_blobs:
        try:
            sshcrypto.verify(ca, cert.signature, cert.signed_bytes)
            ca_ok = True
            break
        except (InvalidSignature, ValueError):
            continue
    if not ca_ok:
        raise VerifyError(
            "certificate is not signed by any trusted Teleport user CA "
            f"(cert says CA={cert.ca_fingerprint}, "
            f"trusted={[fp(c) for c in ca_blobs]})")
    att.ca_fp = cert.ca_fingerprint
    att.signing_key_fp = cert.key_fingerprint
    att.cert_serial = cert.serial

    if cert.cert_type != CERT_TYPE_USER:
        raise VerifyError(f"certificate is not a user certificate "
                          f"(type={cert.cert_type})")

    # ---- 4. the SSHSIG signature itself, over the SSHSIG signed-data blob
    sdata = sshsig.signed_data(s.namespace, s.hash_algorithm, payload, s.reserved)
    try:
        att.sig_algorithm = sshcrypto.verify(cert.pubkey_blob, s.signature, sdata)
    except InvalidSignature:
        raise VerifyError(
            "signature does not match the payload (payload tampered, "
            "or signature does not belong to this payload)")
    except ValueError as e:
        raise VerifyError(f"signature could not be checked: {e}")

    # ---- 5. beam identity from the certificate extensions
    def ext(name):
        v = cert.extensions.get(name)
        return v.decode("utf-8", "replace") if v else ""

    att.bot_name = ext(BOT_NAME_EXT)
    att.bot_instance_id = ext(BOT_INSTANCE_EXT)
    att.delegation_session_id = ext(DELEGATION_EXT)
    att.owner = cert.key_id
    att.principals = cert.valid_principals
    att.login_ip = ext(LOGIN_IP_EXT)
    att.cluster = ext(ROUTE_EXT)
    roles_raw = ext(ROLES_EXT)
    if roles_raw:
        import json
        try:
            att.roles = json.loads(roles_raw).get("roles", [])
        except Exception:
            att.warnings.append(f"could not parse teleport-roles: {roles_raw!r}")

    if require_beam:
        if not att.bot_name:
            raise VerifyError(
                "certificate has no bot-name@goteleport.com extension: this is "
                "an ordinary Teleport user certificate, not a beam identity")
        m = BEAM_BOT_RE.match(att.bot_name)
        if not m:
            raise VerifyError(
                f"bot-name {att.bot_name!r} is not of the form beam-<uuid>; "
                "this is a Machine ID bot but not a beam")
        att.beam_id = m.group(1)
        if expect_beam_id and att.beam_id != expect_beam_id:
            raise VerifyError(
                f"beam id mismatch: signature is from beam {att.beam_id}, "
                f"expected {expect_beam_id}")
        if not att.bot_instance_id:
            att.warnings.append("no bot-instance-id extension")

    # ---- 6. time window
    att.valid_after = cert.valid_after
    att.valid_before = cert.valid_before
    att.claimed_time = claimed_time
    att.claimed_time_source = claimed_time_source
    if claimed_time is not None:
        if not (cert.valid_after <= claimed_time < cert.valid_before):
            raise VerifyError(
                f"claimed time {claimed_time} ({_iso(claimed_time)}) is outside "
                f"the certificate validity window "
                f"{_iso(cert.valid_after)} .. {_iso(cert.valid_before)}; "
                f"the timestamp is self-reported and does not match when the "
                f"signing certificate was valid")
    else:
        att.warnings.append(
            "no claimed time supplied: the signature was only proved to have "
            "been made at SOME point, bounded by the certificate window")

    if "disallow-reissue" not in cert.extensions:
        att.warnings.append(
            "certificate lacks disallow-reissue: it could be used to mint "
            "further certificates")

    att.ok = True
    return att


def render(att: Attestation) -> str:
    L = []
    L.append("BEAM SIGNATURE ATTESTATION")
    L.append("=" * 64)
    L.append(f"  result               : {'VERIFIED' if att.ok else 'FAILED'}")
    L.append(f"  namespace            : {att.namespace}")
    L.append(f"  payload sha256       : {att.payload_sha256}")
    L.append("")
    L.append("  -- signed by --")
    L.append(f"  beam id              : {att.beam_id}")
    L.append(f"  bot name             : {att.bot_name}")
    L.append(f"  bot instance id      : {att.bot_instance_id}   (stable per beam boot)")
    L.append(f"  delegation session   : {att.delegation_session_id}")
    L.append(f"  teleport cluster     : {att.cluster}")
    L.append(f"  owner (cert Key ID)  : {att.owner}   (impersonated human, NOT the signer)")
    L.append(f"  teleport roles       : {', '.join(att.roles)}")
    L.append(f"  cert principals      : {', '.join(att.principals)}")
    L.append(f"  login ip             : {att.login_ip}")
    L.append("")
    L.append("  -- crypto --")
    L.append(f"  signing key          : {att.signing_key_fp}")
    L.append(f"  issuing CA           : {att.ca_fp}")
    L.append(f"  signature algorithm  : {att.sig_algorithm}")
    L.append("")
    L.append("  -- time --")
    L.append(f"  cert valid after     : {att.valid_after} {_iso(att.valid_after)}")
    L.append(f"  cert valid before    : {att.valid_before} {_iso(att.valid_before)}")
    if att.claimed_time is not None:
        L.append(f"  claimed time         : {att.claimed_time} "
                 f"{_iso(att.claimed_time)}  (from {att.claimed_time_source})")
        L.append("  claimed time in window: yes")
    else:
        L.append("  claimed time         : (none supplied)")
    if att.warnings:
        L.append("")
        L.append("  -- warnings --")
        for w in att.warnings:
            L.append(f"  ! {w}")
    return "\n".join(L)
