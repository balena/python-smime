#
# Algorithms and Identifiers for RSA
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc4055
#
from pyasn1.type import tag, namedtype, univ

from pyasn1_modules import rfc2437
from pyasn1_modules.rfc2315 import AlgorithmIdentifier

pkcs_1 = rfc2437.pkcs_1
rsaEncryption = pkcs_1 + (1,)
id_RSAES_OAEP = pkcs_1 + (7,)
id_pSpecified = pkcs_1 + (9,)
id_RSASSA_PSS = pkcs_1 + (10,)
id_mgf1 = pkcs_1 + (8,)

sha224WithRSAEncryption = pkcs_1 + (14,)
sha256WithRSAEncryption = pkcs_1 + (11,)
sha384WithRSAEncryption = pkcs_1 + (12,)
sha512WithRSAEncryption = pkcs_1 + (13,)

id_sha1 = rfc2437.id_sha1

nistHashAlgs = univ.ObjectIdentifier('2.16.840.1.101.3.4.2')

id_sha224 = nistHashAlgs + (4,)
id_sha256 = nistHashAlgs + (1,)
id_sha384 = nistHashAlgs + (2,)
id_sha512 = nistHashAlgs + (3,)

nullOctetString = univ.OctetString('')
nullParameters = univ.Null()


def __instance(klazz, **kwargs):
    object = klazz()
    for k, v in kwargs.iteritems():
        object[k] = v
    return object


sha1Identifier = __instance(AlgorithmIdentifier, algorithm=id_sha1, parameters=nullParameters)
sha224Identifier = __instance(AlgorithmIdentifier, algorithm=id_sha224, parameters=nullParameters)
sha256Identifier = __instance(AlgorithmIdentifier, algorithm=id_sha256, parameters=nullParameters)
sha384Identifier = __instance(AlgorithmIdentifier, algorithm=id_sha384, parameters=nullParameters)
sha512Identifier = __instance(AlgorithmIdentifier, algorithm=id_sha512, parameters=nullParameters)

mgf1SHA1Identifier = __instance(AlgorithmIdentifier, algorithm=id_mgf1, parameters=sha1Identifier)
mgf1SHA224Identifier = __instance(AlgorithmIdentifier, algorithm=id_mgf1, parameters=sha224Identifier)
mgf1SHA256Identifier = __instance(AlgorithmIdentifier, algorithm=id_mgf1, parameters=sha256Identifier)
mgf1SHA384Identifier = __instance(AlgorithmIdentifier, algorithm=id_mgf1, parameters=sha384Identifier)
mgf1SHA512Identifier = __instance(AlgorithmIdentifier, algorithm=id_mgf1, parameters=sha512Identifier)

pSpecifiedEmptyIdentifier = __instance(AlgorithmIdentifier, algorithm=id_pSpecified, parameters=nullOctetString)


class HashAlgorithm(AlgorithmIdentifier):
    """
    HashAlgorithm  ::=  AlgorithmIdentifier
    """
    pass


class MaskGenAlgorithm(AlgorithmIdentifier):
    """
    MaskGenAlgorithm  ::=  AlgorithmIdentifier
    """
    pass


class RSASSA_PSS_params(univ.Sequence):
    """
    RSASSA-PSS-params  ::=  SEQUENCE  {
         hashAlgorithm      [0] HashAlgorithm DEFAULT
                                   sha1Identifier,
         maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
                                   mgf1SHA1Identifier,
         saltLength         [2] INTEGER DEFAULT 20,
         trailerField       [3] INTEGER DEFAULT 1  }
    """
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('hashAlgorithm', HashAlgorithm(sha1Identifier).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.DefaultedNamedType('maskGenAlgorithm', MaskGenAlgorithm(mgf1SHA1Identifier).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.DefaultedNamedType('saltLength', univ.Integer(20).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.DefaultedNamedType('trailerField', univ.Integer(1).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
    )


rSASSA_PSS_Default_Params = __instance(RSASSA_PSS_params,
                                       hashAlgorithm=sha1Identifier,
                                       maskGenAlgorithm=mgf1SHA1Identifier,
                                       saltLength=20,
                                       trailerField=1)

rSASSA_PSS_Default_Identifier = __instance(AlgorithmIdentifier,
                                           algorithm=id_RSASSA_PSS,
                                           parameters=rSASSA_PSS_Default_Params)

rSASSA_PSS_SHA224_Params = __instance(RSASSA_PSS_params,
                                      hashAlgorithm=sha224Identifier,
                                      maskGenAlgorithm=mgf1SHA224Identifier,
                                      saltLength=20,
                                      trailerField=1)

rSASSA_PSS_SHA224_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSASSA_PSS,
                                          parameters=rSASSA_PSS_SHA224_Params)

rSASSA_PSS_SHA256_Params = __instance(RSASSA_PSS_params,
                                      hashAlgorithm=sha256Identifier,
                                      maskGenAlgorithm=mgf1SHA256Identifier,
                                      saltLength=20,
                                      trailerField=1)

rSASSA_PSS_SHA256_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSASSA_PSS,
                                          parameters=rSASSA_PSS_SHA256_Params)

rSASSA_PSS_SHA384_Params = __instance(RSASSA_PSS_params,
                                      hashAlgorithm=sha384Identifier,
                                      maskGenAlgorithm=mgf1SHA384Identifier,
                                      saltLength=20,
                                      trailerField=1)

rSASSA_PSS_SHA384_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSASSA_PSS,
                                          parameters=rSASSA_PSS_SHA384_Params)

rSASSA_PSS_SHA512_Params = __instance(RSASSA_PSS_params,
                                      hashAlgorithm=sha512Identifier,
                                      maskGenAlgorithm=mgf1SHA512Identifier,
                                      saltLength=20,
                                      trailerField=1)

rSASSA_PSS_SHA512_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSASSA_PSS,
                                          parameters=rSASSA_PSS_SHA512_Params)


class RSAES_OAEP_params(univ.Sequence):
    """
    RSAES-OAEP-params  ::=  SEQUENCE  {
         hashFunc          [0] AlgorithmIdentifier DEFAULT
                                  sha1Identifier,
         maskGenFunc       [1] AlgorithmIdentifier DEFAULT
                                  mgf1SHA1Identifier,
         pSourceFunc       [2] AlgorithmIdentifier DEFAULT
                                  pSpecifiedEmptyIdentifier  }
    """
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('hashFunc', AlgorithmIdentifier(sha1Identifier).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.DefaultedNamedType('maskGenFunc', AlgorithmIdentifier(mgf1SHA1Identifier).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.DefaultedNamedType('pSourceFunc', AlgorithmIdentifier(pSpecifiedEmptyIdentifier).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )


rSAES_OAEP_Default_Params = __instance(RSAES_OAEP_params,
                                       hashFunc=sha1Identifier,
                                       maskGenFunc=mgf1SHA1Identifier,
                                       pSourceFunc=pSpecifiedEmptyIdentifier)

rSAES_OAEP_Default_Identifier = __instance(AlgorithmIdentifier,
                                           algorithm=id_RSAES_OAEP,
                                           parameters=rSAES_OAEP_Default_Params)

rSAES_OAEP_SHA224_Params = __instance(RSAES_OAEP_params,
                                      hashFunc=sha224Identifier,
                                      maskGenFunc=mgf1SHA224Identifier,
                                      pSourceFunc=pSpecifiedEmptyIdentifier)

rSAES_OAEP_SHA224_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSAES_OAEP,
                                          parameters=rSAES_OAEP_SHA224_Params)

rSAES_OAEP_SHA256_Params = __instance(RSAES_OAEP_params,
                                      hashFunc=sha256Identifier,
                                      maskGenFunc=mgf1SHA256Identifier,
                                      pSourceFunc=pSpecifiedEmptyIdentifier)

rSAES_OAEP_SHA256_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSAES_OAEP,
                                          parameters=rSAES_OAEP_SHA256_Params)
rSAES_OAEP_SHA384_Params = __instance(RSAES_OAEP_params,
                                      hashFunc=sha384Identifier,
                                      maskGenFunc=mgf1SHA384Identifier,
                                      pSourceFunc=pSpecifiedEmptyIdentifier)

rSAES_OAEP_SHA384_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSAES_OAEP,
                                          parameters=rSAES_OAEP_SHA384_Params)

rSAES_OAEP_SHA512_Params = __instance(RSAES_OAEP_params,
                                      hashFunc=sha512Identifier,
                                      maskGenFunc=mgf1SHA512Identifier,
                                      pSourceFunc=pSpecifiedEmptyIdentifier)

rSAES_OAEP_SHA512_Identifier = __instance(AlgorithmIdentifier,
                                          algorithm=id_RSAES_OAEP,
                                          parameters=rSAES_OAEP_SHA512_Params)

RSAPublicKey = rfc2437.RSAPublicKey
