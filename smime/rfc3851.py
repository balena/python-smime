#
# S/MIME syntax
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc3851
#
from pyasn1.type import tag, namedtype, univ

from pyasn1_modules import rfc2437

import rfc3369
from rfc3369 import IssuerAndSerialNumber, SubjectKeyIdentifier, RecipientKeyIdentifier

id_smime = univ.ObjectIdentifier('1.2.840.113549.1.9.16')
id_cap = univ.ObjectIdentifier('1.2.840.113549.1.9.16.11')
id_cap_preferBinaryInside = univ.ObjectIdentifier('1.2.840.113549.1.9.16.11.1')
id_aa = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2')
id_aa_encrypKeyPref = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.11')
smimeCapabilities = univ.ObjectIdentifier('1.2.840.113549.1.9.15')

md2WithRSAEncryption = rfc2437.md2WithRSAEncryption
md4WithRSAEncryption = rfc2437.md4WithRSAEncryption
md5WithRSAEncryption = rfc2437.md5WithRSAEncryption
sha1WithRSAEncryption = rfc2437.sha1WithRSAEncryption
sha224WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.14')
sha256WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
sha384WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.12')
sha512WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.13')

signingTime = rfc3369.id_signingTime


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
