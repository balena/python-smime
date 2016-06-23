#
# Cryptographic Message Syntax (CMS)
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5652
#
from pyasn1.type import tag, namedtype, namedval, univ, useful

from pyasn1_modules import rfc2315, rfc2459
from pyasn1_modules.rfc2315 import ContentType, GeneralNames, CertificateSerialNumber, UniqueIdentifier, \
    AlgorithmIdentifier, Extensions, Certificate, DigestAlgorithmIdentifiers, CertificateRevocationLists, \
    Attributes, Signature, AttributeValue, EncryptedContentInfo, IssuerAndSerialNumber, EncryptedKey, Digest


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

class CMSVersion(univ.Integer):
    """
    CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) }
    """
    namedValues = namedval.NamedValues(
        ('v0', 0), ('v1', 1), ('v2', 2), ('v3', 3), ('v4', 4)
    )


class Attribute(univ.Sequence):
    """
    Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', univ.SetOf(componentType=AttributeValue()))
    )


class IssuerSerial(univ.Sequence):
    """
    IssuerSerial  ::=  SEQUENCE {
       issuer         GeneralNames,
       serial         CertificateSerialNumber,
       issuerUID      UniqueIdentifier OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', GeneralNames()),
        namedtype.NamedType('serial', CertificateSerialNumber()),
        namedtype.OptionalNamedType('issuerUID', UniqueIdentifier())
    )


class AttCertValidityPeriod(univ.Sequence):
    """
    AttCertValidityPeriod ::= SEQUENCE {
         notBeforeTime  GeneralizedTime,
         notAfterTime   GeneralizedTime
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBeforeTime', useful.GeneralizedTime()),
        namedtype.NamedType('notAfterTime', useful.GeneralizedTime())
    )


class AttCertVersion(univ.Integer):
    """
    AttCertVersion ::= INTEGER { v1(0), v2(1) }
    """
    namedValues = namedval.NamedValues(('v1', 0), ('v2', 1))


class AttributeCertificateInfoV1(univ.Sequence):
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

    class SubjectChoices(univ.Choice):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('baseCertificateID', IssuerSerial().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
            namedtype.NamedType('subjectName', GeneralNames().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        )

    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', AttCertVersion('v1')),
        namedtype.NamedType('subject', SubjectChoices()),
        namedtype.NamedType('issuer', GeneralNames()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('attCertValidityPeriod', AttCertValidityPeriod()),
        namedtype.NamedType('attributes', univ.SequenceOf(Attribute())),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier()),
        namedtype.OptionalNamedType('extensions', Extensions())
    )


class AttributeCertificateV1(univ.Sequence):
    """
    AttributeCertificateV1 ::= SEQUENCE {
         acInfo AttributeCertificateInfoV1,
         signatureAlgorithm AlgorithmIdentifier,
         signature BIT STRING }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('acInfo', AttributeCertificateInfoV1()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signature', univ.BitString())
    )


class ObjectDigestInfo(univ.Sequence):
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

    class DigestedObjectType(univ.Enumerated):
        namedValues = namedval.NamedValues(
            ('publicKey', 0),
            ('publicKeyCert', 1),
            ('otherObjectTypes', 2)
        )

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('digestObjectType', DigestedObjectType()),
        namedtype.OptionalNamedType('otherObjectTypeID', univ.ObjectIdentifier()),
        namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('objectDigest', univ.BitString())
    )


class Holder(univ.Sequence):
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
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('baseCertificateID', IssuerSerial().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('entityName', GeneralNames().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('objectDigestInfo', ObjectDigestInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
    )


class V2Form(univ.Sequence):
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
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('issuerName', GeneralNames()),
        namedtype.OptionalNamedType('baseCertificateID', IssuerSerial().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('objectDigestInfo', ObjectDigestInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
    )


class AttCertIssuer(univ.Choice):
    """
    AttCertIssuer ::= CHOICE {
         v1Form   GeneralNames,  -- MUST NOT be used in this
                                 -- profile
         v2Form   [0] V2Form     -- v2 only
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('v1Form', GeneralNames()),
        namedtype.NamedType('v2Form', V2Form().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    )


class AttributeCertificateInfo(univ.Sequence):
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
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', AttCertVersion('v2')),
        namedtype.NamedType('holder', Holder()),
        namedtype.NamedType('issuer', AttCertIssuer()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('attrCertValidityPeriod', AttCertValidityPeriod()),
        namedtype.NamedType('attributes', univ.SequenceOf(Attribute())),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier()),
        namedtype.OptionalNamedType('extensions', Extensions())
    )


class AttributeCertificate(univ.Sequence):
    """
    AttributeCertificate ::= SEQUENCE {
        acinfo               AttributeCertificateInfo,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('acinfo', AttributeCertificateInfo()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
    )


class AttributeCertificateV2(AttributeCertificate):
    """
    AttributeCertificateV2 ::= AttributeCertificate
    """
    pass


class ExtendedCertificateInfo(univ.Sequence):
    """
    ExtendedCertificateInfo ::= SEQUENCE {
         version CMSVersion,
         certificate Certificate,
         attributes UnauthAttributes }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('certificate', Certificate()),
        namedtype.NamedType('attributes', Attributes())
    )


class ExtendedCertificate(univ.Sequence):
    """
    ExtendedCertificate ::= SEQUENCE {
         extendedCertificateInfo ExtendedCertificateInfo,
         signatureAlgorithm SignatureAlgorithmIdentifier,
         signature Signature }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extendedCertificateInfo', ExtendedCertificateInfo()),
        namedtype.NamedType('signatureAlgorithm', SignatureAlgorithmIdentifier()),
        namedtype.NamedType('signature', Signature())
    )


class CertificateChoices(univ.Choice):
    """
    CertificateChoices ::= CHOICE {
      certificate Certificate,
      extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
      v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
      v2AttrCert [2] IMPLICIT AttributeCertificateV2 }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificate', Certificate()),
        namedtype.NamedType('extendedCertificate', ExtendedCertificate().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('v1AttrCert', AttributeCertificateV1().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('v2AttrCert', AttributeCertificateV2().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
    )


class CertificateSet(univ.SetOf):
    """
    CertificateSet ::= SET OF CertificateChoices
    """
    componentType = CertificateChoices()


# -- 3. General Syntax

id_ct_contentInfo = rfc2315.pkcs_9 + (16, 1, 6)

ContentInfo = rfc2315.ContentInfo

# -- 4. Data Content Type

id_data = rfc2315.data

Data = rfc2315.Data

# -- 5. Signed-data Content Type

id_signedData = rfc2315.signedData


class EncapsulatedContentInfo(univ.Sequence):
    """
    EncapsulatedContentInfo ::= SEQUENCE {
      eContentType ContentType,
      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('eContentType', ContentType()),
        namedtype.OptionalNamedType('eContent', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        ))
    )


class SubjectKeyIdentifier(univ.OctetString):
    """
    SubjectKeyIdentifier ::= OCTET STRING
    """
    pass


class SignerIdentifier(univ.Choice):
    """
    SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', CMSVersion()),
        namedtype.NamedType('subjectKeyIdentifier', SubjectKeyIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )


class SignedAttributes(univ.SetOf):
    """
    SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    componentType = Attribute()


class UnsignedAttributes(univ.SetOf):
    """
    UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    componentType = Attribute()


class SignatureValue(univ.OctetString):
    """
    SignatureValue ::= OCTET STRING
    """
    pass


class SignerInfo(univ.Sequence):
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
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('sid', SignerIdentifier()),
        namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.OptionalNamedType('signedAttrs', SignedAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('signatureAlgorithm', SignatureAlgorithmIdentifier()),
        namedtype.NamedType('signature', SignatureValue()),
        namedtype.OptionalNamedType('unsignedAttrs', UnsignedAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


class SignerInfos(univ.SetOf):
    componentType = SignerInfo()


class SignedData(univ.Sequence):
    """
    SignedData ::= SEQUENCE {
      version CMSVersion,
      digestAlgorithms DigestAlgorithmIdentifiers,
      encapContentInfo EncapsulatedContentInfo,
      certificates [0] IMPLICIT CertificateSet OPTIONAL,
      crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
      signerInfos SignerInfos }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('digestAlgorithms', DigestAlgorithmIdentifiers()),
        namedtype.NamedType('encapContentInfo', EncapsulatedContentInfo()),
        namedtype.OptionalNamedType('certificates', CertificateSet().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('crls', CertificateRevocationLists().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('signerInfos', SignerInfos())
    )


# -- 6. EnvelopedData Type

id_envelopedData = rfc2315.envelopedData


class OriginatorInfo(univ.Sequence):
    """
    OriginatorInfo ::= SEQUENCE {
      certs [0] IMPLICIT CertificateSet OPTIONAL,
      crls [1] IMPLICIT CertificateRevocationLists OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('certs', CertificateSet().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('crls', CertificateRevocationLists().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
    )


class UnprotectedAttributes(univ.SetOf):
    """
    UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    componentType = Attribute()


class RecipientIdentifier(univ.Choice):
    """
    RecipientIdentifier ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      subjectKeyIdentifier [0] SubjectKeyIdentifier }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('subjectKeyIdentifier', SubjectKeyIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    )


class KeyTransRecipientInfo(univ.Sequence):
    """
    KeyTransRecipientInfo ::= SEQUENCE {
      version CMSVersion,  -- always set to 0 or 2
      rid RecipientIdentifier,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('rid', RecipientIdentifier()),
        namedtype.NamedType('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
    )


class OriginatorPublicKey(univ.Sequence):
    """
    OriginatorPublicKey ::= SEQUENCE {
      algorithm AlgorithmIdentifier,
      publicKey BIT STRING }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('publicKey', univ.BitString())
    )


class OriginatorIdentifierOrKey(univ.Choice):
    """
    OriginatorIdentifierOrKey ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      subjectKeyIdentifier [0] SubjectKeyIdentifier,
      originatorKey [1] OriginatorPublicKey }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('subjectKeyIdentifier', SubjectKeyIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('originatorKey', OriginatorPublicKey().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


class UserKeyingMaterial(univ.OctetString):
    """
    UserKeyingMaterial ::= OCTET STRING
    """
    pass


class OtherKeyAttribute(univ.Sequence):
    """
    OtherKeyAttribute ::= SEQUENCE {
      keyAttrId OBJECT IDENTIFIER,
      keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keyAttrId', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('keyAttr', univ.Any())
    )


class RecipientKeyIdentifier(univ.Sequence):
    """
    RecipientKeyIdentifier ::= SEQUENCE {
      subjectKeyIdentifier SubjectKeyIdentifier,
      date GeneralizedTime OPTIONAL,
      other OtherKeyAttribute OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subjectKeyIdentifier', SubjectKeyIdentifier()),
        namedtype.OptionalNamedType('date', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('other', OtherKeyAttribute())
    )


class KeyAgreeRecipientIdentifier(univ.Choice):
    """
    KeyAgreeRecipientIdentifier ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      rKeyId [0] IMPLICIT RecipientKeyIdentifier }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        namedtype.NamedType('rKeyId', RecipientKeyIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    )


class RecipientEncryptedKey(univ.Sequence):
    """
    RecipientEncryptedKey ::= SEQUENCE {
      rid KeyAgreeRecipientIdentifier,
      encryptedKey EncryptedKey }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rid', KeyAgreeRecipientIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
    )


class RecipientEncryptedKeys(univ.SequenceOf):
    """
    RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
    """
    componentType = RecipientEncryptedKey()


class KeyAgreeRecipientInfo(univ.Sequence):
    """
    KeyAgreeRecipientInfo ::= SEQUENCE {
      version CMSVersion,  -- always set to 3
      originator [0] EXPLICIT OriginatorIdentifierOrKey,
      ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      recipientEncryptedKeys RecipientEncryptedKeys }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('originator', OriginatorIdentifierOrKey().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('ukm', UserKeyingMaterial().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('recipientEncryptedKeys', RecipientEncryptedKeys())
    )


class KEKIdentifier(univ.Sequence):
    """
    KEKIdentifier ::= SEQUENCE {
      keyIdentifier OCTET STRING,
      date GeneralizedTime OPTIONAL,
      other OtherKeyAttribute OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keyIdentifier', univ.OctetString()),
        namedtype.NamedType('date', useful.GeneralizedTime()),
        namedtype.NamedType('other', OtherKeyAttribute())
    )


class KEKRecipientInfo(univ.Sequence):
    """
    KEKRecipientInfo ::= SEQUENCE {
      version CMSVersion,  -- always set to 4
      kekid KEKIdentifier,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('kekid', KEKIdentifier()),
        namedtype.NamedType('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
    )


class PasswordRecipientInfo(univ.Sequence):
    """
    PasswordRecipientInfo ::= SEQUENCE {
      version CMSVersion,   -- always set to 0
      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                                 OPTIONAL,
      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
      encryptedKey EncryptedKey }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('keyDerivationAlgorithm', KeyDerivationAlgorithmIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('keyEncryptionAlgorithm', KeyEncryptionAlgorithmIdentifier()),
        namedtype.NamedType('encryptedKey', EncryptedKey())
    )


class OtherRecipientInfo(univ.Sequence):
    """
    OtherRecipientInfo ::= SEQUENCE {
         oriType OBJECT IDENTIFIER,
         oriValue ANY DEFINED BY oriType }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('oriType', univ.ObjectIdentifier()),
        namedtype.NamedType('oriValue', univ.Any())
    )


class RecipientInfo(univ.Choice):
    """
    RecipientInfo ::= CHOICE {
         ktri KeyTransRecipientInfo,
         kari [1] KeyAgreeRecipientInfo,
         kekri [2] KEKRecipientInfo,
         pwri [3] PasswordRecipientInfo,
         ori [4] OtherRecipientInfo }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ktri', KeyTransRecipientInfo()),
        namedtype.NamedType('kari', KeyAgreeRecipientInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('kekri', KEKRecipientInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.NamedType('pwri', PasswordRecipientInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('ori', OtherRecipientInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)))
    )


class RecipientInfos(univ.SetOf):
    """
    RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
    """
    componentType = RecipientInfo()


class EnvelopedData(univ.Sequence):
    """
    EnvelopedData ::= SEQUENCE {
      version CMSVersion,
      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
      recipientInfos RecipientInfos,
      encryptedContentInfo EncryptedContentInfo,
      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.OptionalNamedType('originatorInfo', OriginatorInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('recipientInfos', RecipientInfos()),
        namedtype.NamedType('encryptedContentInfo', EncryptedContentInfo()),
        namedtype.OptionalNamedType('unprotectedAttrs', UnprotectedAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


# -- 7. Digested-data Content Type

id_digestedData = rfc2315.digestedData


class DigestedData(univ.Sequence):
    """
    DigestedData ::= SEQUENCE {
      version CMSVersion,
      digestAlgorithm DigestAlgorithmIdentifier,
      encapContentInfo EncapsulatedContentInfo,
      digest Digest }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.NamedType('encapContentInfo', EncapsulatedContentInfo()),
        namedtype.NamedType('digest', Digest())
    )


# -- 8. Encrypted-data Content Type

id_encryptedData = rfc2315.encryptedData


class EncryptedData(univ.Sequence):
    """
    EncryptedData ::= SEQUENCE {
      version CMSVersion,
      encryptedContentInfo EncryptedContentInfo,
      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('encryptedContentInfo', EncryptedContentInfo()),
        namedtype.OptionalNamedType('unprotectedAttrs', UnprotectedAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


# -- 9. Authenticated-data Content Type

id_authenticatedData = rfc2315.pkcs_9 + (16, 1, 2)


class AuthAttributes(univ.SetOf):
    """
    AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    componentType = Attribute()


class UnauthAttributes(univ.SetOf):
    """
    UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
    """
    componentType = Attribute()


class MessageAuthenticationCode(univ.OctetString):
    """
    MessageAuthenticationCode ::= OCTET STRING
    """
    pass


class AuthenticatedData(univ.Sequence):
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
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.OptionalNamedType('originatorInfo', OriginatorInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('recipientInfos', RecipientInfos()),
        namedtype.NamedType('macAlgorithm', MessageAuthenticationCodeAlgorithm()),
        namedtype.OptionalNamedType('digestAlgorithm', DigestAlgorithmIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('encapContentInfo', EncapsulatedContentInfo()),
        namedtype.OptionalNamedType('authAttrs', AuthAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.NamedType('mac', MessageAuthenticationCode()),
        namedtype.OptionalNamedType('unauthAttrs', UnauthAttributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
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


class Time(univ.Choice):
    """
    Time ::= CHOICE {
        utcTime          UTCTime,
        generalizedTime  GeneralizedTime }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalizedTime', useful.GeneralizedTime())
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
