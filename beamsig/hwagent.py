"""Client for Teleport's hardware key agent (gRPC over TLS on a unix socket).

The tbot identity file does NOT contain private key material. It contains a
PIV slot reference; the actual key lives behind this agent. The agent listens
on $TELEPORT_KEY_AGENT_DIR/agent.sock and speaks gRPC wrapped in TLS, using
$TELEPORT_KEY_AGENT_DIR/cert.pem as both the server cert and the CA the client
is expected to pin. There is NO client authentication.
"""
import os
import sys

_GEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gen")
if _GEN not in sys.path:
    sys.path.insert(0, _GEN)

import grpc  # noqa: E402
from teleport.hardwarekeyagent.v1 import hardwarekeyagent_service_pb2 as pb  # noqa: E402
from teleport.hardwarekeyagent.v1 import hardwarekeyagent_service_pb2_grpc as pbg  # noqa: E402

from .identity import DEFAULT_AGENT_DIR  # noqa: E402

HASH_NONE = pb.HASH_NONE
HASH_SHA256 = pb.HASH_SHA256
HASH_SHA512 = pb.HASH_SHA512


class HardwareKeyAgent:
    def __init__(self, agent_dir: str = None):
        self.dir = agent_dir or DEFAULT_AGENT_DIR
        sock = os.path.join(self.dir, "agent.sock")
        cert = os.path.join(self.dir, "cert.pem")
        with open(cert, "rb") as f:
            ca = f.read()
        creds = grpc.ssl_channel_credentials(root_certificates=ca)
        self.channel = grpc.secure_channel(
            "unix://" + sock, creds,
            options=[("grpc.ssl_target_name_override", "localhost")])
        self.stub = pbg.HardwareKeyAgentServiceStub(self.channel)

    def ping(self, timeout=10) -> int:
        return self.stub.Ping(pb.PingRequest(), timeout=timeout).pid

    def sign(self, key_ref, digest: bytes, hash_alg=HASH_SHA256,
             command="beamsig", proxy_host="", username="", cluster_name="",
             timeout=30) -> bytes:
        """Return a DER-encoded ECDSA signature over `digest`."""
        req = pb.SignRequest(
            digest=digest,
            hash=hash_alg,
            salt_length=0,
            key_ref=pb.KeyRef(
                serial_number=key_ref.serial_number,
                slot_key=key_ref.slot_enum,
                public_key_der=key_ref.public_key_der,
            ),
            key_info=pb.KeyInfo(
                touch_required=key_ref.touch_required,
                pin_required=key_ref.pin_required,
                proxy_host=proxy_host or os.environ.get("TELEPORT_CLUSTER", ""),
                username=username,
                cluster_name=cluster_name or os.environ.get("TELEPORT_CLUSTER", ""),
            ),
            command=command,
        )
        return self.stub.Sign(req, timeout=timeout).signature
