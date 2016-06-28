import six
from smime.crypto.asn1 import oid, types, tag
from smime.crypto.asn1 import x509_common
from smime.crypto.asn1 import x509_name
from smime.crypto.asn1 import x509_time
from smime.crypto.asn1 import x509_extension
from smime.crypto.asn1 import x509


# -- 10.1. Algorithm Identifier Types

_ALGORITHM_IDENTIFIER_DICT = {
    oid.RSA_ENCRYPTION: types.Null,
    oid.ID_AES128_CBC: types.OctetString,
    oid.ID_AES192_CBC: types.OctetString,
    oid.ID_AES256_CBC: types.OctetString
}

class AlgorithmIdentifier(types.Sequence):
    components = (
        (types.Component("algorithm", oid.ObjectIdentifier)),
        (types.Component("parameters", types.Any, optional=True,
                         defined_by="algorithm", lookup=_ALGORITHM_IDENTIFIER_DICT))
        )


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
    pass


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
        return int(value)


@types.Universal(10, tag.PRIMITIVE)
class Enumerated(types.Simple):
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
        raise TypeError("Cannot assign unknown label to enumerated type")

    def _encode_value(self):
        return types.encode_int(self._value)

    @classmethod
    def _decode_value(self, buf, strict=True):
        return types.decode_int(buf, strict=strict)


class ContentType(oid.ObjectIdentifier):
    pass


class CMSVersion(LabeledInteger):
    """
    CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) }
    """
    labels = (('v0', 0), ('v1', 1), ('v2', 2), ('v3', 3), ('v4', 4))


class SetOfAttributes(types.SetOf):
    print_labels = False
    print_delimiter = ", "
    component = x509_name.AttributeValue


# TODO: map X.509 attributes + ContentType, MessageDigest, SigningTime, Countersignature
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


class IssuerSerial(types.Sequence):
    """
    IssuerSerial  ::=  SEQUENCE {
       issuer         GeneralNames,
       serial         CertificateSerialNumber,
       issuerUID      UniqueIdentifier OPTIONAL
    }
    """
    components = (
        (types.Component('issuer', x509_name.GeneralNames)),
        (types.Component('serial', x509_common.CertificateSerialNumber)),
        (types.Component('issuerUID', x509_common.UniqueIdentifier, optional=True))
        )


class AttCertValidityPeriod(types.Sequence):
    """
    AttCertValidityPeriod ::= SEQUENCE {
         notBeforeTime  GeneralizedTime,
         notAfterTime   GeneralizedTime
    }
    """
    components = (
        (types.Component('notBeforeTime', x509_time.GeneralizedTime)),
        (types.Component('notAfterTime', x509_time.GeneralizedTime))
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
        print_labels = True
        components = {
            'baseCertificateID': IssuerSerial.implicit(0),
            'subjectName': x509_name.GeneralNames.implicit(1)
        }

    components = (
        (types.Component('version', AttCertVersion, default='v1')),
        (types.Component('subject', SubjectChoices)),
        (types.Component('issuer', x509_name.GeneralNames)),
        (types.Component('signature', x509_common.AlgorithmIdentifier)),
        (types.Component('serialNumber', x509_common.CertificateSerialNumber)),
        (types.Component('attCertValidityPeriod', AttCertValidityPeriod)),
        (types.Component('attributes', SequenceOfAttributes)),
        (types.Component('issuerUniqueID', x509_common.UniqueIdentifier, optional=True)),
        (types.Component('extensions', x509_extension.Extensions, optional=True))
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
        (types.Component('signatureAlgorithm', x509_common.AlgorithmIdentifier)),
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
        (types.Component('digestAlgorithm', x509_common.AlgorithmIdentifier)),
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
        (types.Component('entityName', x509_name.GeneralNames.implicit(1), optional=True)),
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
        (types.Component('issuerName', x509_name.GeneralNames, optional=True)),
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
    print_labels = True
    components = {
        'v1Form': x509_name.GeneralNames,
        'v2Form': V2Form.implicit(0)
        }


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
        (types.Component('signature', x509_common.AlgorithmIdentifier)),
        (types.Component('serialNumber', x509_common.CertificateSerialNumber)),
        (types.Component('attrCertValidityPeriod', AttCertValidityPeriod)),
        (types.Component('attributes', SequenceOfAttributes)),
        (types.Component('issuerUniqueID', x509_common.UniqueIdentifier, optional=True)),
        (types.Component('extensions', x509_extension.Extensions, optional=True))
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
        (types.Component('signatureAlgorithm', x509_common.AlgorithmIdentifier)),
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
        (types.Component('certificate', x509.Certificate)),
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
    print_labels = True
    components = {
        'certificate': x509.Certificate,
        'extendedCertificate': ExtendedCertificate.implicit(0),
        'v1AttrCert': AttributeCertificateV1.implicit(1),
        'v2AttrCert': AttributeCertificateV2.implicit(2)
        }


class CertificateSet(types.SetOf):
    """
    CertificateSet ::= SET OF CertificateChoices
    """
    print_labels = False
    print_delimiter = ", "
    component = CertificateChoices


class EncapsulatedContentInfo(types.Sequence):
    """
    EncapsulatedContentInfo ::= SEQUENCE {
      eContentType ContentType,
      eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    """
    components = (
        (types.Component('eContentType', ContentType)),
        (types.Component('eContent', types.OctetString.implicit(0), optional=True))
        )


class SubjectKeyIdentifier(types.OctetString):
    """
    SubjectKeyIdentifier ::= OCTET STRING
    """
    pass


class IssuerAndSerialNumber(types.Sequence):
    components = (
        (types.Component('issuer', x509_name.Name)),
        (types.Component('serialNumber', x509_common.CertificateSerialNumber))
        )


class SignerIdentifier(types.Choice):
    """
    SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
    """
    print_labels = True
    components = {
        'issuerAndSerialNumber': IssuerAndSerialNumber,
        'subjectKeyIdentifier': SubjectKeyIdentifier.implicit(0)
        }


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
        (types.Component('signedAttrs', SignedAttributes.implicit(0), optional=True)),
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
        (types.Component('revocationDate', x509_time.UTCTime))
        )


class CRLEntries(types.SequenceOf):
    component = CRLEntry


class TBSCertificateRevocationList(types.Sequence):
    components = (
        (types.Component('signature', x509_common.AlgorithmIdentifier)),
        (types.Component('issuer', x509_name.Name)),
        (types.Component('lastUpdate', x509_time.UTCTime)),
        (types.Component('nextUpdate', x509_time.UTCTime)),
        (types.Component('revokedCertificates', CRLEntries, optional=True))
        )


class CertificateRevocationList(types.Sequence):
    componentType = (
        (types.Component('tbsCertificateRevocationList', TBSCertificateRevocationList)),
        (types.Component('signatureAlgorithm', x509_common.AlgorithmIdentifier)),
        (types.Component('signature', types.BitString))
        )


class CertificateRevocationLists(types.SetOf):
    component = CertificateRevocationList


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
    print_labels = True
    components = {
        'issuerAndSerialNumber': IssuerAndSerialNumber,
        'subjectKeyIdentifier': SubjectKeyIdentifier.implicit(0)
        }


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
        (types.Component('algorithm', x509_common.AlgorithmIdentifier)),
        (types.Component('publicKey', types.BitString))
        )


class OriginatorIdentifierOrKey(types.Choice):
    """
    OriginatorIdentifierOrKey ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      subjectKeyIdentifier [0] SubjectKeyIdentifier,
      originatorKey [1] OriginatorPublicKey }
    """
    print_labels = True
    components = {
        'issuerAndSerialNumber': IssuerAndSerialNumber,
        'subjectKeyIdentifier': SubjectKeyIdentifier.implicit(0),
        'originatorKey': OriginatorPublicKey.implicit(1)
        }


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
        (types.Component('keyAttr', types.Any, optional=True))
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
        (types.Component('date', x509_time.GeneralizedTime, optional=True)),
        (types.Component('other', OtherKeyAttribute, optional=True))
        )


class KeyAgreeRecipientIdentifier(types.Choice):
    """
    KeyAgreeRecipientIdentifier ::= CHOICE {
      issuerAndSerialNumber IssuerAndSerialNumber,
      rKeyId [0] IMPLICIT RecipientKeyIdentifier }
    """
    print_labels = True
    components = {
        'issuerAndSerialNumber': IssuerAndSerialNumber,
        'rKeyId': RecipientKeyIdentifier.implicit(0)
        }


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
        (types.Component('date', x509_time.GeneralizedTime, optional=True)),
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
    print_labels = True
    components = {
        'ktri': KeyTransRecipientInfo,
        'kari': KeyAgreeRecipientInfo.implicit(1),
        'kekri': KEKRecipientInfo.implicit(2),
        'pwri': PasswordRecipientInfo.implicit(3),
        'ori': OtherRecipientInfo.implicit(4)
        }


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
        (types.Component('encryptedContent', EncryptedContent.implicit(0), optional=True))
        )


class Digest(types.OctetString):
    pass


class MessageAuthenticationCode(types.OctetString):
    """
    MessageAuthenticationCode ::= OCTET STRING
    """
    pass
