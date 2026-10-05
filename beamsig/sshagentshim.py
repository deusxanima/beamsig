"""An ssh-agent that fronts the Teleport hardware key agent.

Exposes two identities:
  1. the full Teleport SSH user certificate (ecdsa-sha2-nistp256-cert-v01@openssh.com)
  2. the bare public key

and proxies SSH_AGENTC_SIGN_REQUEST to the hardware key agent, which holds the
only copy of the private key. This lets stock ssh-keygen/git sign with the
beam identity: they only ever see a signing oracle, never key material.
"""
import base64
import hashlib
import os
import socket
import socketserver
import struct
import sys
import threading

from . import identity as ident_mod
from .hwagent import HardwareKeyAgent, HASH_SHA256
from .wire import Reader, Writer

SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_EXTENSION = 27
SSH_AGENT_EXTENSION_FAILURE = 28


def der_to_ssh_ecdsa_sig(keytype: str, der: bytes) -> bytes:
    """Convert a DER ECDSA signature into an SSH signature blob."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    inner = Writer().mpint(r).mpint(s).bytes()
    return Writer().string(keytype).string(inner).bytes()


class Shim:
    """Re-reads the identity file on EVERY request.

    tbot replaces the certificate every ~20 minutes (in place, same inode).
    A shim that caches the certificate blob at startup starts failing with
    "agent refused operation" as soon as the first renewal lands, because the
    client offers the new certificate blob and the agent no longer recognises
    it. The bare public key is stable, but the certificate blob is not.
    """

    def __init__(self, identity_path=None, agent_dir=None):
        self.identity_path = identity_path
        self.hw = HardwareKeyAgent(agent_dir)
        self.hw.ping()
        self._cert_blob = None
        self.reload()

    def reload(self):
        ident = ident_mod.load(self.identity_path)
        if ident.hw_key is None:
            raise SystemExit("identity has no PIV hardware key reference; "
                             "this shim only supports hardware-backed identities")
        self.ident = ident
        parts = ident.ssh_cert_line.split()
        self.cert_type = parts[0].decode()
        cert_blob = base64.b64decode(parts[1])
        self.key_type = self.cert_type.replace("-cert-v01@openssh.com", "")
        r = Reader(cert_blob)
        r.string()                       # cert type name
        r.string()                       # nonce
        curve = r.string()               # curve name
        point = r.string()               # ec point
        self.bare_blob = Writer().string(self.key_type).string(curve).string(point).bytes()
        if cert_blob != self._cert_blob:
            if self._cert_blob is not None:
                sys.stderr.write("beamsig-agent: certificate rotated, reloaded\n")
                sys.stderr.flush()
            self._cert_blob = cert_blob
        self.cert_blob = cert_blob
        alias = os.environ.get("BEAM_ALIAS", "")
        self.identities = [
            (self.cert_blob, f"beam-cert {alias}".strip()),
            (self.bare_blob, f"beam-key {alias}".strip()),
        ]

    def handle(self, msg: bytes) -> bytes:
        if not msg:
            return Writer().u8(SSH_AGENT_FAILURE).bytes()
        t, body = msg[0], msg[1:]
        self.reload()   # the certificate changes every ~20 minutes
        if t == SSH_AGENTC_REQUEST_IDENTITIES:
            w = Writer().u8(SSH_AGENT_IDENTITIES_ANSWER).u32(len(self.identities))
            for blob, comment in self.identities:
                w.string(blob).string(comment)
            return w.bytes()
        if t == SSH_AGENTC_SIGN_REQUEST:
            return self.sign(body)
        return Writer().u8(SSH_AGENT_FAILURE).bytes()

    def sign(self, body: bytes) -> bytes:
        r = Reader(body)
        keyblob = r.string()
        data = r.string()
        try:
            flags = r.u32()
        except Exception:
            flags = 0
        if keyblob not in (self.cert_blob, self.bare_blob):
            sys.stderr.write(
                "beamsig-agent: sign request for an unknown key blob "
                "(stale certificate? the current cert was reloaded from %s)\n"
                % (self.identity_path or ident_mod.DEFAULT_IDENTITY))
            return Writer().u8(SSH_AGENT_FAILURE).bytes()
        digest = hashlib.sha256(data).digest()
        try:
            der = self.hw.sign(self.ident.hw_key, digest, HASH_SHA256,
                               command="beamsig ssh-agent sign (flags=%d)" % flags)
        except Exception as e:
            sys.stderr.write(f"beamsig-agent: hardware agent sign failed: {e}\n")
            return Writer().u8(SSH_AGENT_FAILURE).bytes()
        sig = der_to_ssh_ecdsa_sig(self.key_type, der)
        return Writer().u8(SSH_AGENT_SIGN_RESPONSE).string(sig).bytes()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        buf = b""
        while True:
            while len(buf) < 4:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                buf += chunk
            n = struct.unpack(">I", buf[:4])[0]
            if n > 1 << 20:
                return
            while len(buf) < 4 + n:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                buf += chunk
            msg, buf = buf[4:4 + n], buf[4 + n:]
            try:
                resp = self.server.shim.handle(msg)
            except Exception as e:
                sys.stderr.write(f"beamsig-agent: {e}\n")
                resp = Writer().u8(SSH_AGENT_FAILURE).bytes()
            sock.sendall(struct.pack(">I", len(resp)) + resp)


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path, shim):
        self.shim = shim
        super().__init__(path, Handler)


def serve(sock_path: str, identity_path=None, agent_dir=None):
    shim = Shim(identity_path, agent_dir)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    old = os.umask(0o077)
    try:
        srv = Server(sock_path, shim)
    finally:
        os.umask(old)
    return srv
