from smime.crypto.asn1 import types
from smime.crypto.asn1 import x509_time
from smime.crypto.asn1 import cms_common


class MessageDigest(types.OctetString):
    """
    MessageDigest ::= OCTET STRING
    """
    pass


class Time(types.Choice):
    """
    Time ::= CHOICE {
        utcTime          UTCTime,
        generalizedTime  GeneralizedTime }
    """
    components = (
        (types.Component('utcTime', x509_time.UTCTime)),
        (types.Component('generalizedTime', x509_time.GeneralizedTime))
        )


class SigningTime(Time):
    """
    SigningTime ::= Time
    """
    pass


class Countersignature(cms_common.SignerInfo):
    """
    Countersignature ::= SignerInfo
    """
    pass