"""Build CMS SignedData (PKCS#7) using the Teleport hardware key agent.

`openssl cms -sign` cannot be used on a beam: the tbot identity file holds a
PIV slot reference, not a private key, so OpenSSH/OpenSSL have nothing to load.
We therefore assemble the CMS structure ourselves and obtain the one signature
we need from the agent. The output is verifiable by stock
`openssl cms -verify`.
"""
import hashlib

from asn1crypto import algos, cms, core, pem, util, x509

from .hwagent import HardwareKeyAgent, HASH_SHA256


def build_signed_data(payload: bytes, leaf_pem: bytes, hw: HardwareKeyAgent,
                      key_ref, detached: bool = False,
                      signing_time=None, extra_certs=()) -> bytes:
    """Return DER-encoded CMS ContentInfo/SignedData over `payload`."""
    if leaf_pem.lstrip().startswith(b"-----"):
        _, _, der = pem.unarmor(leaf_pem)
    else:
        der = leaf_pem
    leaf = x509.Certificate.load(der)

    digest = hashlib.sha256(payload).digest()

    attrs = [
        cms.CMSAttribute({
            "type": "content_type",
            "values": [cms.ContentType("data")],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(digest)],
        }),
    ]
    if signing_time is not None:
        attrs.append(cms.CMSAttribute({
            "type": "signing_time",
            "values": [cms.Time({"utc_time": signing_time})],
        }))
    signed_attrs = cms.CMSAttributes(attrs)

    # RFC 5652 5.4: the signature is over the DER of the SignedAttrs as an
    # explicit SET OF, NOT the implicitly-tagged [0] form stored in SignerInfo.
    to_sign = signed_attrs.dump()
    sig = hw.sign(key_ref, hashlib.sha256(to_sign).digest(), HASH_SHA256,
                  command="beamsig cms sign")

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": leaf.issuer,
                "serial_number": leaf.serial_number,
            })
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm(
            {"algorithm": "sha256_ecdsa"}),
        "signature": core.OctetString(sig),
    })

    certs = [leaf]
    for c in extra_certs:
        if c.lstrip().startswith(b"-----"):
            _, _, d = pem.unarmor(c)
        else:
            d = c
        certs.append(x509.Certificate.load(d))

    # SignedData._encap_content_info_spec() returns ContentInfo only once
    # self['version'] reads as 'v1'. Constructing SignedData from a single dict
    # hits a chicken-and-egg: the nested dict is resolved before version is
    # readable, yielding EncapsulatedContentInfo, which the outer field then
    # rejects. Build the Sequence incrementally instead, version first.
    encap = {"content_type": "data"}
    if not detached:
        encap["content"] = core.OctetString(payload)

    signed_data = cms.SignedData()
    signed_data["version"] = "v1"
    signed_data["digest_algorithms"] = [algos.DigestAlgorithm({"algorithm": "sha256"})]
    signed_data["encap_content_info"] = encap
    signed_data["certificates"] = cms.CertificateSet(
        [cms.CertificateChoices({"certificate": c}) for c in certs])
    signed_data["signer_infos"] = cms.SignerInfos([signer_info])

    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


def to_pem(der: bytes) -> bytes:
    return pem.armor(b"CMS", der)
