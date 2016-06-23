#
# S/MIME syntax
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5751
#
from pyasn1.type import tag, namedtype, univ

from pyasn1_modules import rfc2315, rfc2437

import rfc5652
from rfc5652 import IssuerAndSerialNumber, SubjectKeyIdentifier, RecipientKeyIdentifier

id_smime = rfc2315.pkcs_9 + (16,)

id_cap = id_smime + (11,)
id_cap_preferBinaryInside = id_cap + (1,)

id_aa = id_smime + (2,)
id_aa_encrypKeyPref = id_aa + (11,)

smimeCapabilities = id_smime + (15,)

md2WithRSAEncryption = rfc2437.md2WithRSAEncryption
md4WithRSAEncryption = rfc2437.md4WithRSAEncryption
md5WithRSAEncryption = rfc2437.md5WithRSAEncryption
sha1WithRSAEncryption = rfc2437.sha1WithRSAEncryption

signingTime = rfc5652.id_signingTime


class SMIMECapability(univ.Sequence):
    """
    SMIMECapability ::= SEQUENCE {
       capabilityID OBJECT IDENTIFIER,
       parameters ANY DEFINED BY capabilityID OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('capabilityID', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )


class SMIMECapabilities(univ.SequenceOf):
    """
    SMIMECapabilities ::= SEQUENCE OF SMIMECapability
    """
    componentType = SMIMECapability()


class SMIMEEncryptionKeyPreference(univ.Choice):
    """
    SMIMEEncryptionKeyPreference ::= CHOICE {
       issuerAndSerialNumber   [0] IssuerAndSerialNumber,
       recipientKeyId          [1] RecipientKeyIdentifier,
       subjectAltKeyIdentifier [2] SubjectKeyIdentifier
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('recipientKeyId', RecipientKeyIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('subjectAltKeyIdentifier', SubjectKeyIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
    )


class SMIMECapabilitiesParametersForRC2CBC(univ.Integer):
    """
    SMIMECapabilitiesParametersForRC2CBC ::= INTEGER
    """
    pass
