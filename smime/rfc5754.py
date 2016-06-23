#
# SHA2 algorithms
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5751
#
from pyasn1.type import univ

# -- Message Digest Algorithms

id_sha224 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.4')
id_sha256 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
id_sha384 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.2')
id_sha512 = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.3')


# -- 3. Signature Algorithms

# -- 3.1. DSA

id_dsa_with_sha224 = univ.ObjectIdentifier('2.16.840.1.101.3.4.3.1')
id_dsa_with_sha256 = univ.ObjectIdentifier('2.16.840.1.101.3.4.3.2')


# -- 3.2. RSA

sha224WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.14')
sha256WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
sha384WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.12')
sha512WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.13')


# -- 3.3. ECDSA

ecdsa_with_SHA224 = univ.ObjectIdentifier('1.2.840.10045.4.3.1')
ecdsa_with_SHA256 = univ.ObjectIdentifier('1.2.840.10045.4.3.2')
ecdsa_with_SHA384 = univ.ObjectIdentifier('1.2.840.10045.4.3.3')
ecdsa_with_SHA512 = univ.ObjectIdentifier('1.2.840.10045.4.3.4')
