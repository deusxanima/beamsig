"""An in-toto-flavoured attestation envelope for beam-signed artifacts.

Envelope layout (DSSE-like, but using SSHSIG as the signature primitive so
that stock OpenSSH tooling can at least inspect it):

    {
      "payloadType": "application/vnd.beamsig.statement+json",
      "payload":     "<base64 of the canonical statement JSON>",
      "signatures": [{"sshsig": "<armored SSHSIG over the raw statement>"}]
    }

The statement is signed in the SSHSIG namespace "beamsig.attestation.v1".
Every beam fact that a verifier should rely on is taken from the certificate
embedded in the SSHSIG, NOT from the statement body. Fields in the statement
that cannot be proved (notably the beam alias and the wall-clock signing time)
live under `selfReported` and are rendered as untrusted.
"""
import base64
import datetime
import hashlib
import json
import os

STATEMENT_TYPE = "https://beamsig.dev/Statement/v1"
PREDICATE_TYPE = "https://beamsig.dev/BeamProvenance/v1"
PAYLOAD_TYPE = "application/vnd.beamsig.statement+json"
NAMESPACE = "beamsig.attestation.v1"


def canonical(obj) -> bytes:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_statement(subjects, predicate_extra=None) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    stmt = {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            # Anything here is ADVISORY. The authoritative copy of beam id,
            # bot instance id, cluster, roles and the validity window comes
            # from the certificate inside the signature.
            "selfReported": {
                "beamAlias": os.environ.get("BEAM_ALIAS", ""),
                "beamId": os.environ.get("BEAM_ID", ""),
                "cluster": os.environ.get("TELEPORT_CLUSTER", ""),
                "signedAt": now.isoformat(),
                "note": ("beamAlias and signedAt are NOT bound by the Teleport "
                         "certificate and must be treated as unverified claims"),
            },
        },
    }
    if predicate_extra:
        stmt["predicate"].update(predicate_extra)
    return stmt


def build_envelope(statement: dict, sign_fn) -> dict:
    payload = canonical(statement)
    sig = sign_fn(payload, NAMESPACE)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"sshsig": sig.decode()}],
    }


def open_envelope(env: dict):
    """Return (statement_dict, raw_payload_bytes, armored_sshsig_bytes)."""
    if env.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError(f"unexpected payloadType {env.get('payloadType')!r}")
    raw = base64.b64decode(env["payload"])
    stmt = json.loads(raw)
    if canonical(stmt) != raw:
        raise ValueError("payload is not canonical JSON; refusing to verify "
                         "(a non-canonical payload allows two readings of the "
                         "same signed bytes)")
    sigs = env.get("signatures") or []
    if len(sigs) != 1:
        raise ValueError(f"expected exactly 1 signature, got {len(sigs)}")
    return stmt, raw, sigs[0]["sshsig"].encode()
