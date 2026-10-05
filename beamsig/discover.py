"""Opt-in, lazy pinning of a Teleport user CA for an unseen tenant.

Teams do not all share one Beams tenant, so a repository can hold commits from
several. The signature carries the certificate, and the certificate names the
cluster it claims to come from, so in principle a verifier can fetch that
cluster's CA on demand and carry on.

Read this before enabling it.

**The cluster name comes from the artifact being verified.** Fetching a trust
anchor named by the thing you are trying to trust is circular. An attacker who
mints their own CA and a certificate claiming
`teleport-route-to-cluster=evil.example.com` will, under discovery, cause us to
fetch evil.example.com's CA, which will of course validate their certificate.
The result is not meaningless -- it shows the signer controls a Teleport
cluster at that hostname -- but it is emphatically not "trusted", and it is not
the same statement as a pin an operator chose.

So discovery is:

  * off unless asked for;
  * restricted to an explicit hostname allowlist, so "any tenant under
    *.beams.sh" can be expressed without accepting arbitrary hosts;
  * trust-on-first-use -- the fetched CA is written to the store and pinned
    from then on, so a later change of CA is visible rather than silent;
  * and always reported as discovered rather than operator-pinned.

It is a convenience for a team whose tenants are all its own. It is not a
substitute for pinning.
"""
import fnmatch
import os
import re
import urllib.request

from .verify import TrustAnchor, load_trust_anchors

CLUSTER_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,252}[a-zA-Z0-9])?$")


class DiscoveryRefused(Exception):
    """Discovery was not attempted, and why."""


def allowed(cluster: str, patterns) -> bool:
    if not cluster or not CLUSTER_RE.match(cluster) or ".." in cluster:
        return False
    return any(fnmatch.fnmatch(cluster, p) for p in (patterns or []))


def pin_path(store: str, cluster: str) -> str:
    return os.path.join(store, f"{cluster}.ca")


def discover(cluster: str, store: str, patterns, timeout=20) -> list:
    """Fetch and pin `cluster`'s user CA. Returns the new TrustAnchors.

    Raises DiscoveryRefused when the cluster is not covered by the allowlist,
    which is the common and expected case.
    """
    if not patterns:
        raise DiscoveryRefused(
            "discovery is disabled; pass --discover-allow '<pattern>' (or set "
            "BEAMSIG_DISCOVER_ALLOW) to permit fetching CAs for clusters "
            "named by the certificate itself, and read beamsig/discover.py "
            "first")
    if not allowed(cluster, patterns):
        raise DiscoveryRefused(
            f"cluster {cluster!r} is not covered by the discovery allowlist "
            f"{list(patterns)}; pin it explicitly with `beamsig trust "
            f"{cluster}` if you mean to trust it")

    dest = pin_path(store, cluster)
    if os.path.exists(dest):
        # Already pinned. If we are here the pin did not match, which means the
        # cluster's CA changed (rotation) or something is wrong. Do not
        # silently overwrite a pin.
        raise DiscoveryRefused(
            f"a pin for {cluster!r} already exists at {dest} but did not "
            "verify this certificate. The cluster's user CA may have been "
            "rotated; confirm the new fingerprint out of band and replace the "
            "file deliberately")

    url = f"https://{cluster}/webapi/auth/export?type=user"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        data = r.read()
    os.makedirs(store, mode=0o700, exist_ok=True)
    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, dest)
    anchors = load_trust_anchors([dest])
    for a in anchors:
        a.discovered = True
    return anchors


def allow_patterns(explicit=None):
    """Allowlist from flags and/or $BEAMSIG_DISCOVER_ALLOW (comma separated)."""
    pats = list(explicit or [])
    env = os.environ.get("BEAMSIG_DISCOVER_ALLOW", "")
    pats += [p.strip() for p in env.split(",") if p.strip()]
    return pats
