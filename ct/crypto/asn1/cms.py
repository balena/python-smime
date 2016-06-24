#
# Cryptographic Message Syntax (CMS)
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5652
#
import six
from ct.crypto.asn1 import oid, types, tag
from ct.crypto.asn1.x509_common import AlgorithmIdentifier, CertificateSerialNumber, UniqueIdentifier
from ct.crypto.asn1.x509_name import Name, AttributeValue, GeneralNames
from ct.crypto.asn1.x509_time import GeneralizedTime, UTCTime
from ct.crypto.asn1.x509_extension import Extensions
from ct.crypto.asn1.x509 import Certificate

# -- 10.1. Algorithm Identifier Types

class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    """
    DigestAlgorithmIdentifier ::= AlgorithmIdentifier
    """
    pass


class SignatureAlgorithmIdentifier(AlgorithmIdentifier):
    """
    SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
    """
    pass


class KeyEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    """
    KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    """


class ContentEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    """
    ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
    """
    pass


class MessageAuthenticationCodeAlgorithm(AlgorithmIdentifier):
    """
    MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier
    """
    pass


class KeyDerivationAlgorithmIdentifier(AlgorithmIdentifier):
    """
    KeyDerivationAlgorithmIdentifier ::= AlgorithmIdentifier
    """
    pass


# -- Preamble: General Definitions

class LabeledInteger(types.Integer):
    labels = ()

    def __str__(self):
        for k, v in self.labels:
            if v == self._value:
                return k
        return 'unk(%d)' % self._value

    @classmethod
    def _convert_value(self, value):
        if isinstance(value, six.string_types):
            for k, v in self.labels:
                if k == value:
                    return v
        return value


@types.Universal(10, tag.PRIMITIVE)
class Enumerated(LabeledInteger):
    pass


class ContentType(oid.ObjectIdentifier):
    pass


# TODO: defined_by
class ContentInfo(types.Sequence):
    components = (
        (types.Component('contentType', ContentType)),
        (types.Component('content', types.Any.explicit(0), optional=True))
        )


class CMSVersion(LabeledInteger):
    """
    CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) }
    """
    labels = (('v0', 0), ('v1', 1), ('v2', 2), ('v3', 3), ('v4', 4))


class SetOfAttributes(types.SetOf):
    print_labels = False
    print_delimiter = ", "
    component = AttributeValue


class Attribute(types.Sequence):
    """
    Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }
    """
    components = (
        (types.Component('type', oid.ObjectIdentifier)),
        (types.Component('values', SetOfAttributes))
        )


class IssuerSerial(types.Sequence):
    """
    IssuerSerial  ::=  SEQUENCE {
       issuer         GeneralNames,
       serial         CertificateSerialNumber,
       issuerUID      UniqueIdentifier OPTIONAL
    }
    """
    components = (
        (types.Component('issuer', GeneralNames)),
        (types.Component('serial', CertificateSerialNumber)),
        (types.Component('issuerUID', UniqueIdentifier, optional=True))
        )


class AttCertValidityPeriod(types.Sequence):
    """
    AttCertValidityPeriod ::= SEQUENCE {
         notBeforeTime  GeneralizedTime,
         notAfterTime   GeneralizedTime
    }
    """
    components = (
        (types.Component('notBeforeTime', GeneralizedTime)),
        (types.Component('notAfterTime', GeneralizedTime))
        )


class AttCertVersion(LabeledInteger):
    """
    AttCertVersion ::= INTEGER { v1(0), v2(1) }
    """
    labels = (('v1', 0), ('v2', 1))


class SequenceOfAttributes(types.SequenceOf):
    print_delimiter = ", "
    component = Attribute


class AttributeCertificateInfoV1(types.Sequence):
    """
    AttributeCertificateInfoV1 ::= SEQUENCE {
         version AttCertVersionV1 DEFAULT v1,
         subject CHOICE {
           baseCertificateID [0] IssuerSerial,
             -- associated with a Public Key Certificate
           subjectName [1] GeneralNames },
             -- associated with a name
         issuer GeneralNames,
         signature AlgorithmIdentifier,
         serialNumber CertificateSerialNumber,
         attCertValidityPeriod AttCertValidityPeriod,
         attributes SEQUENCE OF Attribute,
         issuerUniqueID UniqueIdentifier OPTIONAL,
         extensions Extensions OPTIONAL }
    """

    class SubjectChoices(types.Choice):
        components = (
            (types.Component('baseCertificateID', IssuerSerial.implicit(0))),
            (types.Component('subjectName', GeneralNames.implicit(1)))
        )

    components = (
        (types.Component('version', AttCertVersion, default='v1')),
        (types.Component('subject', SubjectChoices)),
        (types.Component('issuer', GeneralNames)),
        (types.Component('signature', AlgorithmIdentifier)),
        (types.Component('serialNumber', CertificateSerialNumber)),
        (types.Component('attCertValidityPeriod', AttCertValidityPeriod)),
        (types.Component('attributes', SequenceOfAttributes)),
        (types.Component('issuerUniqueID', UniqueIdentifier, optional=True)),
        (types.Component('extensions', Extensions, optional=True))
        )


class AttributeCertificateV1(types.Sequence):
    """
    AttributeCertificateV1 ::= SEQUENCE {
         acInfo AttributeCertificateInfoV1,
         signatureAlgorithm AlgorithmIdentifier,
         signature BIT STRING }
    """
    components = (
        (types.Component('acInfo', AttributeCertificateInfoV1)),
        (types.Component('signatureAlgorithm', AlgorithmIdentifier)),
        (types.Component('signature', types.BitString))
        )


class ObjectDigestInfo(types.Sequence):
    """
    ObjectDigestInfo ::= SEQUENCE {
         digestedObjectType  ENUMERATED {
                 publicKey            (0),
                 publicKeyCert        (1),
                 otherObjectTypes     (2) },
                         -- otherObjectTypes MUST NOT
                         -- be used in this profile
         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
         digestAlgorithm     AlgorithmIdentifier,
         objectDigest        BIT STRING
    }
    """
    class DigestedObjectType(Enumerated):
        values = (
            ('publicKey', 0),
            ('publicKeyCert', 1),
            ('otherObjectTypes', 2)
        )

    components = (
        (types.Component('digestObjectType', DigestedObjectType)),
        (types.Component('otherObjectTypeID', oid.ObjectIdentifier, optional=True)),
        (types.Component('digestAlgorithm', AlgorithmIdentifier)),
        (types.Component('objectDigest', types.BitString))
        )


class Holder(types.Sequence):
    """
    Holder ::= SEQUENCE {
          baseCertificateID   [0] IssuerSerial OPTIONAL,
                   -- the issuer and serial number of
                   -- the holder's Public Key Certificate
          entityName          [1] GeneralNames OPTIONAL,
                   -- the name of the claimant or role
          objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
                   -- used to directly authenticate the holder,
                   -- for example, an executable
    }
    """
    components = (
        (types.Component('baseCertificateID', IssuerSerial.implicit(0), optional=True)),
        (types.Component('entityName', GeneralNames.implicit(1), optional=True)),
        (types.Component('objectDigestInfo', ObjectDigestInfo.implicit(2), optional=True))
        )


class V2Form(types.Sequence):
    """
    V2Form ::= SEQUENCE {
         issuerName            GeneralNames  OPTIONAL,
         baseCertificateID     [0] IssuerSerial  OPTIONAL,
         objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
           -- issuerName MUST be present in this profile
           -- baseCertificateID and objectDigestInfo MUST NOT
           -- be present in this profile
    }
    """
    components = (
        (types.Component('issuerName', GeneralNames, optional=True)),
        (types.Component('baseCertificateID', IssuerSerial.implicit(0), optional=True)),
        (types.Component('objectDigestInfo', ObjectDigestInfo.implicit(1), optional=True))
        )


class AttCertIssuer(types.Choice):
    """
    AttCertIssuer ::= CHOICE {
         v1Form   GeneralNames,  -- MUST NOT be used in this
                                 -- profile
         v2Form   [0] V2Form     -- v2 only
    }
    """
    components = (
        (types.Component('v1Form', GeneralNames)),
        (types.Component('v2Form', V2Form.implicit(0)))
        )


class AttributeCertificateInfo(types.Sequence):
    """
    AttributeCertificateInfo ::= SEQUENCE {
         version              AttCertVersion -- version is v2,
         holder               Holder,
         issuer               AttCertIssuer,
         signature            AlgorithmIdentifier,
         serialNumber         CertificateSerialNumber,
         attrCertValidityPeriod   AttCertValidityPeriod,
         attributes           SEQUENCE OF Attribute,
         issuerUniqueID       UniqueIdentifier OPTIONAL,
         extensions           Extensions OPTIONAL
    }
    """
    components = (
        (types.Component('version', AttCertVersion, default='v2')),
        (types.Component('holder', Holder)),
        (types.Component('issuer', AttCertIssuer)),
        (types.Component('signature', AlgorithmIdentifier)),
        (types.Component('serialNumber', CertificateSerialNumber)),
        (types.Component('attrCertValidityPeriod', AttCertValidityPeriod)),
        (types.Component('attributes', SequenceOfAttributes)),
        (types.Component('issuerUniqueID', UniqueIdentifier, optional=True)),
        (types.Component('extensions', Extensions, optional=True))
        )


class AttributeCertificate(types.Sequence):
    """
    AttributeCertificate ::= SEQUENCE {
        acinfo               AttributeCertificateInfo,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING
    }
    """
    components = (
        (types.Component('acinfo', AttributeCertificateInfo)),
        (types.Component('signatureAlgorithm', AlgorithmIdentifier)),
        (types.Component('signatureValue', types.BitString))
        )


class AttributeCertificateV2(AttributeCertificate):
    """
    AttributeCertificateV2 ::= AttributeCertificate
    """
    pass


class ExtendedCertificateInfo(types.Sequence):
    """
    ExtendedCertificateInfo ::= SEQUENCE {
         version CMSVersion,
         certificate Certificate,
         attributes UnauthAttributes }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('certificate', Certificate)),
        (types.Component('attributes', UnauthAttributes))
        )


class Signature(types.BitString):
    pass


class ExtendedCertificate(types.Sequence):
    """
    ExtendedCertificate ::= SEQUENCE {
         extendedCertificateInfo ExtendedCertificateInfo,
         signatureAlgorithm SignatureAlgorithmIdentifier,
         signature Signature }
    """
    components = (
        (types.Component('extendedCertificateInfo', ExtendedCertificateInfo)),
        (types.Component('signatureAlgorithm', SignatureAlgorithmIdentifier)),
        (types.Component('signature', Signature))
        )


class CertificateChoices(types.Choice):
    """
    CertificateChoices ::= CHOICE {
      certificate Certificate,
      extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
      v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
      v2AttrCert [2] IMPLICIT AttributeCertificateV2 }
    """
    print_labels = True  # Print component type.
    components = (
        (types.Component('certificate', Certificate)),
        (types.Component('extendedCertificate', ExtendedCertificate.implicit(0))),
        (types.Component('v1AttrCert', AttributeCertificateV1.implicit(1))),
        (types.Component('v2AttrCert', AttributeCertificateV2.implicit(2)))
        )


class CertificateSet(types.SetOf):
    """
    CertificateSet ::= SET OF CertificateChoices
    """
    print_labels = False
    print_delimiter = ", "
    component = CertificateChoices()


# -- 3. General Syntax

id_ct_contentInfo = rfc2315.pkcs_9 + (16, 1, 6)

# -- 4. Data Content Type

id_data = rfc2315.data

# -- 5. Signed-data Content Type

id_signedData = rfc2315.signedData


class EncapsulatedContentInfo(types.Sequence):
    """
    EncapsulatedContentInfo ::= SEQUENCE {
      eContentType ContentType,
      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    """
    components = (
        (types.Component('eContentType', ContentType)),
        (types.Component('eContent', types.OctetString().implicit(0), optional=True))
        )


class SubjectKeyIdentifier(types.OctetString):
    """
    SubjectKeyIdentifier ::= OCTET STRING
    """
    pass


class IssuerAndSerialNumber(types.Sequence):
    components = (
        (types.Component('issuer', Name)),
        (types.Component('serialNumber', CertificateSerialNumber))
        )


class SignerIdentifier(types.Choice):
    """
    SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
    """
    print_labels = True  # Print component type.
    components = (
        (types.Component('issuerAndSerialNumber', IssuerAndSerialNumber)),
        (types.Component('subjectKeyIdentifier', SubjectKeyIdentifier.implicit(0)))
        )


class SignedAttributes(types.SetOf):
    """
    SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    component = Attribute


class UnsignedAttributes(types.SetOf):
    """
    UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    component = Attribute


class SignatureValue(types.OctetString):
    """
    SignatureValue ::= OCTET STRING
    """
    pass


class SignerInfo(types.Sequence):
    """
    SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('sid', SignerIdentifier)),
        (types.Component('digestAlgorithm', DigestAlgorithmIdentifier)),
        (types.Component('signedAttrs', SignedAttributes().implicit(0), optional=True)),
        (types.Component('signatureAlgorithm', SignatureAlgorithmIdentifier)),
        (types.Component('signature', SignatureValue)),
        (types.Component('unsignedAttrs', UnsignedAttributes.implicit(1), optional=True))
        )


class SignerInfos(types.SetOf):
    component = SignerInfo


class DigestAlgorithmIdentifiers(types.SetOf):
    component = DigestAlgorithmIdentifier


class SerialNumber(types.Integer):
    pass


class CRLEntry(types.Sequence):
    components = (
        (types.Component('userCertificate', SerialNumber)),
        (types.Component('revocationDate', UTCTime))
        )


class CRLEntries(types.SequenceOf):
    component = CRLEntry


class TBSCertificateRevocationList(types.Sequence):
    components = (
        (types.Component('signature', AlgorithmIdentifier)),
        (types.Component('issuer', Name)),
        (types.Component('lastUpdate', UTCTime)),
        (types.Component('nextUpdate', UTCTime)),
        (types.Component('revokedCertificates', CRLEntries, optional=True))
        )


class CertificateRevocationList(types.Sequence):
    componentType = (
        (types.Component('tbsCertificateRevocationList', TBSCertificateRevocationList)),
        (types.Component('signatureAlgorithm', AlgorithmIdentifier)),
        (types.Component('signature', types.BitString))
        )


class CertificateRevocationLists(types.SetOf):
    component = CertificateRevocationList


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
        (types.Component('version', CMSVersion)),
        (types.Component('digestAlgorithms', DigestAlgorithmIdentifiers)),
        (types.Component('encapContentInfo', EncapsulatedContentInfo)),
        (types.Component('certificates', CertificateSet.implicit(0), optional=True)),
        (types.Component('crls', CertificateRevocationLists.implicit(1), optional=True)),
        (types.Component('signerInfos', SignerInfos))
        )


# -- 6. EnvelopedData Type

id_envelopedData = rfc2315.envelopedData


class OriginatorInfo(types.Sequence):
    """
    OriginatorInfo ::= SEQUENCE {
      certs [0] IMPLICIT CertificateSet OPTIONAL,
      crls [1] IMPLICIT CertificateRevocationLists OPTIONAL }
    """
    components = (
        (types.Component('certs', CertificateSet.implicit(0), optional=True)),
        (types.Component('crls', CertificateRevocationLists.implicit(1), optional=True)),
        )


class UnprotectedAttributes(types.SetOf):
    """
    UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    component = Attribute


class RecipientIdentifier(types.Choice):
    """
    RecipientIdentifier ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      subjectKeyIdentifier [0] SubjectKeyIdentifier }
    """
    components = (
        (types.Component('issuerAndSerialNumber', IssuerAndSerialNumber)),
        (types.Component('subjectKeyIdentifier', SubjectKeyIdentifier.implicit(0)))
        )


class EncryptedKey(types.OctetString):
    pass


class KeyTransRecipientInfo(types.Sequence):
    """
    KeyTransRecipientInfo ::= SEQUENCE {
      version CMSVersion,  -- always set to 0 or 2
      rid RecipientIdentifier,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('rid', RecipientIdentifier)),
        (types.Component('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier)),
        (types.Component('encryptedKey', EncryptedKey))
        )


class OriginatorPublicKey(types.Sequence):
    """
    OriginatorPublicKey ::= SEQUENCE {
      algorithm AlgorithmIdentifier,
      publicKey BIT STRING }
    """
    components = (
        (types.Component('algorithm', AlgorithmIdentifier)),
        (types.Component('publicKey', types.BitString))
        )


class OriginatorIdentifierOrKey(types.Choice):
    """
    OriginatorIdentifierOrKey ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      subjectKeyIdentifier [0] SubjectKeyIdentifier,
      originatorKey [1] OriginatorPublicKey }
    """
    components = (
        (types.Component('issuerAndSerialNumber', IssuerAndSerialNumber)),
        (types.Component('subjectKeyIdentifier', SubjectKeyIdentifier.implicit(0))),
        (types.Component('originatorKey', OriginatorPublicKey.implicit(1)))
        )


class UserKeyingMaterial(types.OctetString):
    """
    UserKeyingMaterial ::= OCTET STRING
    """
    pass


class OtherKeyAttribute(types.Sequence):
    """
    OtherKeyAttribute ::= SEQUENCE {
      keyAttrId OBJECT IDENTIFIER,
      keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
    """
    components = (
        (types.Component('keyAttrId', oid.ObjectIdentifier)),
        (types.Component('keyAttr', types.Any(), optional=True))
        )


class RecipientKeyIdentifier(types.Sequence):
    """
    RecipientKeyIdentifier ::= SEQUENCE {
      subjectKeyIdentifier SubjectKeyIdentifier,
      date GeneralizedTime OPTIONAL,
      other OtherKeyAttribute OPTIONAL }
    """
    components = (
        (types.Component('subjectKeyIdentifier', SubjectKeyIdentifier)),
        (types.Component('date', GeneralizedTime, optional=True)),
        (types.Component('other', OtherKeyAttribute, optional=True))
        )


class KeyAgreeRecipientIdentifier(types.Choice):
    """
    KeyAgreeRecipientIdentifier ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      rKeyId [0] IMPLICIT RecipientKeyIdentifier }
    """
    components = (
        (types.Component('issuerAndSerialNumber', IssuerAndSerialNumber)),
        (types.Component('rKeyId', RecipientKeyIdentifier.implicit(0)))
        )


class RecipientEncryptedKey(types.Sequence):
    """
    RecipientEncryptedKey ::= SEQUENCE {
      rid KeyAgreeRecipientIdentifier,
      encryptedKey EncryptedKey }
    """
    components = (
        (types.Component('rid', KeyAgreeRecipientIdentifier)),
        (types.Component('encryptedKey', EncryptedKey))
        )


class RecipientEncryptedKeys(types.SequenceOf):
    """
    RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
    """
    component = RecipientEncryptedKey


class KeyAgreeRecipientInfo(types.Sequence):
    """
    KeyAgreeRecipientInfo ::= SEQUENCE {
      version CMSVersion,  -- always set to 3
      originator [0] EXPLICIT OriginatorIdentifierOrKey,
      ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      recipientEncryptedKeys RecipientEncryptedKeys }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('originator', OriginatorIdentifierOrKey.explicit(0))),
        (types.Component('ukm', UserKeyingMaterial.explicit(1), optional=True)),
        (types.Component('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier)),
        (types.Component('recipientEncryptedKeys', RecipientEncryptedKeys))
        )


class KEKIdentifier(types.Sequence):
    """
    KEKIdentifier ::= SEQUENCE {
      keyIdentifier OCTET STRING,
      date GeneralizedTime OPTIONAL,
      other OtherKeyAttribute OPTIONAL }
    """
    components = (
        (types.Component('keyIdentifier', types.OctetString)),
        (types.Component('date', GeneralizedTime, optional=True)),
        (types.Component('other', OtherKeyAttribute, optional=True))
        )


class KEKRecipientInfo(types.Sequence):
    """
    KEKRecipientInfo ::= SEQUENCE {
      version CMSVersion,  -- always set to 4
      kekid KEKIdentifier,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('kekid', KEKIdentifier)),
        (types.Component('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier)),
        (types.Component('encryptedKey', EncryptedKey))
        )


class PasswordRecipientInfo(types.Sequence):
    """
    PasswordRecipientInfo ::= SEQUENCE {
      version CMSVersion,   -- always set to 0
      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                                 OPTIONAL,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('keyDerivationAlgorithm', KeyDerivationAlgorithmIdentifier.implicit(0), optional=True)),
        (types.Component('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier)),
        (types.Component('encryptedKey', EncryptedKey))
        )


class OtherRecipientInfo(types.Sequence):
    """
    OtherRecipientInfo ::= SEQUENCE {
         oriType OBJECT IDENTIFIER,
         oriValue ANY DEFINED BY oriType }
    """
    components = (
        (types.Component('oriType', oid.ObjectIdentifier)),
        (types.Component('oriValue', types.Any))
        )


class RecipientInfo(types.Choice):
    """
    RecipientInfo ::= CHOICE {
         ktri KeyTransRecipientInfo,
         kari [1] KeyAgreeRecipientInfo,
         kekri [2] KEKRecipientInfo,
         pwri [3] PasswordRecipientInfo,
         ori [4] OtherRecipientInfo }
    """
    components = (
        (types.Component('ktri', KeyTransRecipientInfo)),
        (types.Component('kari', KeyAgreeRecipientInfo.implicit(1))),
        (types.Component('kekri', KEKRecipientInfo.implicit(2))),
        (types.Component('pwri', PasswordRecipientInfo.implicit(3))),
        (types.Component('ori', OtherRecipientInfo.implicit(4)))
        )


class RecipientInfos(types.SetOf):
    """
    RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
    """
    component = RecipientInfo


class EncryptedContent(types.OctetString):
    pass


class EncryptedContentInfo(types.Sequence):
    components = (
        (types.Component('contentType', ContentType)),
        (types.Component('contentEncryptionAlgorithm', ContentEncryptionAlgorithmIdentifier)),
        (types.Component('encryptedContent', EncryptedContent().implicit(0), optional=True))
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
        (types.Component('version', CMSVersion)),
        (types.Component('originatorInfo', OriginatorInfo.implicit(0), optional=True)),
        (types.Component('recipientInfos', RecipientInfos)),
        (types.Component('encryptedContentInfo', EncryptedContentInfo)),
        (types.Component('unprotectedAttrs', UnprotectedAttributes.implicit(1)))
        )


# -- 7. Digested-data Content Type

id_digestedData = rfc2315.digestedData


class Digest(types.OctetString):
    pass


class DigestedData(types.Sequence):
    """
    DigestedData ::= SEQUENCE {
      version CMSVersion,
      digestAlgorithm DigestAlgorithmIdentifier,
      encapContentInfo EncapsulatedContentInfo,
      digest Digest }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('digestAlgorithm', DigestAlgorithmIdentifier)),
        (types.Component('encapContentInfo', EncapsulatedContentInfo)),
        (types.Component('digest', Digest))
        )


# -- 8. Encrypted-data Content Type

id_encryptedData = rfc2315.encryptedData


class EncryptedData(types.Sequence):
    """
    EncryptedData ::= SEQUENCE {
      version CMSVersion,
      encryptedContentInfo EncryptedContentInfo,
      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
    """
    components = (
        (types.Component('version', CMSVersion)),
        (types.Component('encryptedContentInfo', EncryptedContentInfo)),
        (types.Component('unprotectedAttrs', UnprotectedAttributes.implicit(1), optional=True))
        )


# -- 9. Authenticated-data Content Type

id_authenticatedData = rfc2315.pkcs_9 + (16, 1, 2)


class AuthAttributes(types.SetOf):
    """
    AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    component = Attribute


class UnauthAttributes(types.SetOf):
    """
    UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    components = Attribute


class MessageAuthenticationCode(types.OctetString):
    """
    MessageAuthenticationCode ::= OCTET STRING
    """
    pass


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
        (types.Component('version', CMSVersion)),
        (types.Component('originatorInfo', OriginatorInfo.implicit(0), optional=True)),
        (types.Component('recipientInfos', RecipientInfos)),
        (types.Component('macAlgorithm', MessageAuthenticationCodeAlgorithm)),
        (types.Component('digestAlgorithm', DigestAlgorithmIdentifier.implicit(1), optional=True)),
        (types.Component('encapContentInfo', EncapsulatedContentInfo)),
        (types.Component('authAttrs', AuthAttributes.implicit(2), optional=True)),
        (types.Component('mac', MessageAuthenticationCode)),
        (types.Component('unauthAttrs', UnauthAttributes.implicit(3), optional=True))
        )


# -- 11. Useful Attributes

# -- 11.1. Content Type

id_contentType = rfc2315.pkcs_9 + (3,)

# -- 11.2. Message Digest

id_messageDigest = rfc2315.pkcs_9 + (4,)


class MessageDigest(univ.OctetString):
    """
    MessageDigest ::= OCTET STRING
    """
    pass


# -- 11.3. Signing Time

id_signingTime = rfc2315.pkcs_9 + (5,)


class Time(types.Choice):
    """
    Time ::= CHOICE {
        utcTime          UTCTime,
        generalizedTime  GeneralizedTime }
    """
    components = (
        (types.Component('utcTime', UTCTime)),
        (types.Component('generalizedTime', GeneralizedTime))
        )


class SigningTime(Time):
    """
    SigningTime ::= Time
    """
    pass


# -- 11.4. Countersignature

id_countersignature = rfc2315.pkcs_9 + (6,)


class Countersignature(SignerInfo):
    """
    Countersignature ::= SignerInfo
    """
    pass
