// Fetching a cluster's user CA on demand, and deciding which clusters we will
// ask. Shared by the background worker (which fetches) and the content script
// (which parses), so the host check cannot drift between them.
//
// Why this is safe to do at all. The cluster name in a certificate
// (`teleport-route-to-cluster`) is just a claim until the certificate has been
// checked against that cluster's CA, so "fetch the CA from whatever cluster the
// cert names" would let anyone run their own cluster and look verified. Two
// things make it sound here:
//
//   1. We only ever contact clusters under a domain the user trusts
//      (default `beams.sh`). The trust anchor is "TLS to <tenant>.beams.sh",
//      not the cert's say-so.
//   2. After the chain verifies, the cluster INSIDE the signed certificate must
//      equal the host the CA came from (see verify.js), so a cert cannot be
//      checked against one cluster's CA while claiming another.
//
// This is weaker than a pin, and the panel says so. Pinned CAs are still tried
// first, and a fetch happens only when no pinned CA matches.
(function (root) {
  "use strict";

  const ns = (root.Beamsig = root.Beamsig || {});

  const DEFAULT_TRUSTED_DOMAINS = ["beams.sh"];
  const MAX_EXPORT_BYTES = 20000;
  const MAX_CA_LINES = 10;

  // A bare, lowercase DNS hostname: no scheme, port, path, userinfo or IP
  // literal. Anything else is refused before it can reach fetch().
  const HOSTNAME_RE =
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

  // `domains` entries may be written "beams.sh", ".beams.sh" or "*.beams.sh".
  // Only SUBDOMAINS match: the apex is not a tenant, and `evilbeams.sh` or
  // `beams.sh.evil.com` must not match.
  function normaliseDomains(domains) {
    return (domains || [])
      .map((d) => String(d).trim().toLowerCase().replace(/^\*?\./, ""))
      .filter(Boolean);
  }

  function isTrustedCluster(cluster, domains) {
    if (typeof cluster !== "string" || !HOSTNAME_RE.test(cluster)) return false;
    return normaliseDomains(domains).some((d) => cluster.endsWith("." + d));
  }

  function exportUrl(cluster) {
    return `https://${cluster}/webapi/auth/export?type=user`;
  }

  // Turn a `/webapi/auth/export?type=user` body into entries that
  // verify.loadPinnedCAs understands. The export is one
  // `cert-authority <type> <key> clustername=<name>&type=user` line per active
  // CA (more than one during a rotation). A line naming a DIFFERENT cluster than
  // the one we asked is dropped rather than trusted.
  function parseExport(text, cluster) {
    const out = [];
    for (const raw of String(text).split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      if (!/\bAAAA\S+/.test(line)) continue;
      const m = /clustername=([^&\s]+)/.exec(line);
      if (m && m[1] !== cluster) continue;
      out.push({ cluster, line, fetchedFrom: cluster });
      if (out.length >= MAX_CA_LINES) break;
    }
    return out;
  }

  ns.cafetch = {
    DEFAULT_TRUSTED_DOMAINS,
    MAX_EXPORT_BYTES,
    isTrustedCluster,
    normaliseDomains,
    exportUrl,
    parseExport,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
