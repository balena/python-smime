#
# SHA2 algorithms
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5751
#
from pyasn1.type import univ
import rfc4055

# -- Message Digest Algorithms

id_sha1 = rfc4055.id_sha1
id_sha224 = rfc4055.id_sha224
id_sha256 = rfc4055.id_sha256
id_sha384 = rfc4055.id_sha384
id_sha512 = rfc4055.id_sha512


# -- 3. Signature Algorithms

# -- 3.1. DSA

nistSignAlgs = univ.ObjectIdentifier('2.16.840.1.101.3.4.3')
id_dsa_with_sha224 = nistSignAlgs + (1,)
id_dsa_with_sha256 = nistSignAlgs + (2,)


# -- 3.2. RSA

sha224WithRSAEncryption = rfc4055.sha224WithRSAEncryption
sha256WithRSAEncryption = rfc4055.sha256WithRSAEncryption
sha384WithRSAEncryption = rfc4055.sha384WithRSAEncryption
sha512WithRSAEncryption = rfc4055.sha512WithRSAEncryption


# -- 3.3. ECDSA

ecdsa_with_SHA2 = univ.ObjectIdentifier('1.2.840.10045.4.3')
ecdsa_with_SHA224 = ecdsa_with_SHA2 + (1,)
ecdsa_with_SHA256 = ecdsa_with_SHA2 + (2,)
ecdsa_with_SHA384 = ecdsa_with_SHA2 + (3,)
ecdsa_with_SHA512 = ecdsa_with_SHA2 + (4,)
