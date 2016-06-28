#
# Cryptographic Message Syntax (CMS)
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5652
#
from base64 import b64decode
from smime.crypto.asn1 import oid, types
from smime.crypto.asn1 import cms_common


class SignedData(types.Sequence):
    """
    SignedData ::= SEQUENCE {
      version CMSVersion,
      digestAlgorithms DigestAlgorithmIdentifiers,
      encapContentInfo EncapsulatedContentInfo,
      certificates [0] IMPLICIT CertificateSet OPTIONAL,
      crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
      signerInfos SignerInfos }
    """
    components = (
        (types.Component('version', cms_common.CMSVersion)),
        (types.Component('digestAlgorithms', cms_common.DigestAlgorithmIdentifiers)),
        (types.Component('encapContentInfo', cms_common.EncapsulatedContentInfo)),
        (types.Component('certificates', cms_common.CertificateSet.implicit(0), optional=True)),
        (types.Component('crls', cms_common.CertificateRevocationLists.implicit(1), optional=True)),
        (types.Component('signerInfos', cms_common.SignerInfos))
        )


class EnvelopedData(types.Sequence):
    """
    EnvelopedData ::= SEQUENCE {
      version CMSVersion,
      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
      recipientInfos RecipientInfos,
      encryptedContentInfo EncryptedContentInfo,
      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
    """
    components = (
        (types.Component('version', cms_common.CMSVersion)),
        (types.Component('originatorInfo', cms_common.OriginatorInfo.implicit(0), optional=True)),
        (types.Component('recipientInfos', cms_common.RecipientInfos)),
        (types.Component('encryptedContentInfo', cms_common.EncryptedContentInfo)),
        (types.Component('unprotectedAttrs', cms_common.UnprotectedAttributes.implicit(1), optional=True))
        )


class DigestedData(types.Sequence):
    """
    DigestedData ::= SEQUENCE {
      version CMSVersion,
      digestAlgorithm DigestAlgorithmIdentifier,
      encapContentInfo EncapsulatedContentInfo,
      digest Digest }
    """
    components = (
        (types.Component('version', cms_common.CMSVersion)),
        (types.Component('digestAlgorithm', cms_common.DigestAlgorithmIdentifier)),
        (types.Component('encapContentInfo', cms_common.EncapsulatedContentInfo)),
        (types.Component('digest', cms_common.Digest))
        )


class EncryptedData(types.Sequence):
    """
    EncryptedData ::= SEQUENCE {
      version CMSVersion,
      encryptedContentInfo EncryptedContentInfo,
      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
    """
    components = (
        (types.Component('version', cms_common.CMSVersion)),
        (types.Component('encryptedContentInfo', cms_common.EncryptedContentInfo)),
        (types.Component('unprotectedAttrs', cms_common.UnprotectedAttributes.implicit(1), optional=True))
        )


class AuthenticatedData(types.Sequence):
    """
    AuthenticatedData ::= SEQUENCE {
      version CMSVersion,
      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
      recipientInfos RecipientInfos,
      macAlgorithm MessageAuthenticationCodeAlgorithm,
      digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
      encapContentInfo EncapsulatedContentInfo,
      authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
      mac MessageAuthenticationCode,
      unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
    """
    components = (
        (types.Component('version', cms_common.CMSVersion)),
        (types.Component('originatorInfo', cms_common.OriginatorInfo.implicit(0), optional=True)),
        (types.Component('recipientInfos', cms_common.RecipientInfos)),
        (types.Component('macAlgorithm', cms_common.MessageAuthenticationCodeAlgorithm)),
        (types.Component('digestAlgorithm', cms_common.DigestAlgorithmIdentifier.implicit(1), optional=True)),
        (types.Component('encapContentInfo', cms_common.EncapsulatedContentInfo)),
        (types.Component('authAttrs', cms_common.AuthAttributes.implicit(2), optional=True)),
        (types.Component('mac', cms_common.MessageAuthenticationCode)),
        (types.Component('unauthAttrs', cms_common.UnauthAttributes.implicit(3), optional=True))
        )


_CONTENT_TYPE_DICT = {
    oid.ID_DATA: types.OctetString,
    oid.ID_SIGNED_DATA: SignedData,
    oid.ID_ENVELOPED_DATA: EnvelopedData,
    oid.ID_DIGESTED_DATA: DigestedData,
    oid.ID_ENCRYPTED_DATA: EncryptedData,
    oid.ID_AUTHENTICATED_DATA: AuthenticatedData
    }


class ContentInfo(types.Sequence):
    components = (
        (types.Component('contentType', cms_common.ContentType)),
        (types.Component('content', types.Any.explicit(0), optional=True,
                         defined_by='contentType', lookup=_CONTENT_TYPE_DICT))
        )


def from_string(der, strict_der=True):
    """Read a DER-encoded message from a string.

    Args:
        der: a DER encoded message
        strict_der: if False, tolerate some non-fatal DER errors.

    Returns:
        ContentInfo object.

    Raises:
        smime.crypto.ASN1Error: a block was invalid
        IOError: the file could not be read.
    """
    return ContentInfo.decode(der, strict=strict_der)


def from_file(der_file, strict_der=True):
    """Read a DER-encoded message from a file.

    Args:
        der_file: a DER encoded file.
        strict_der: if False, tolerate some non-fatal DER errors.

    Returns:
        ContentInfo object.

    Raises:
        smime.crypto.error.ASN1Error: a block was invalid
        IOError: the file could not be read.
    """
    with open(der_file, 'rb') as f:
        return from_string(f.read(), strict_der=strict_der)