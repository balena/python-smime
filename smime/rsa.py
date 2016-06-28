from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from smime.crypto import cert
from smime.crypto.asn1 import oid, types


class ASN1_RSAPublicKey(types.Sequence):
    components = (
        (types.Component('modulus', types.Integer)),
        (types.Component('publicExponent', types.Integer))
        )


class RSAPublicKey():
    oid = oid.RSA_ENCRYPTION

    def __init__(self, pubkey):
        x509_certs = cert.certs_from_pem(pubkey)
        self._x509_cert = x509_certs.next()._asn1_cert
        der = self._get_public_rsa_key(self._x509_cert)
        self._key = RSA.importKey(der)
        self._cipher = PKCS1_v1_5.new(self._key)

    def _get_public_rsa_key(self, x509_cert):
        bits = x509_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'].value
        return self._bits_to_bytearray(bits)

    @staticmethod
    def _bits_to_bytearray(s):
        assert len(s) % 8 == 0
        result = []
        while s:
            byte = int(''.join([str(x) for x in s[:8]]), 2)
            result.append(chr(byte))
            s = s[8:]
        return ''.join(result)

    def get_cert(self):
        return self._x509_cert

    def encrypt(self, data):
        return self._cipher.encrypt(data)

    def get_parameters(self):
        return {'n': self._key.key.n, 'e': self._key.key.e}

    def __str__(self):
        parms = self.get_parameters()
        return 'RSAPublicKey(n=%d, e=%d)' % (parms['n'], parms['e'])