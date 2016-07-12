from __future__ import unicode_literals

from abc import ABCMeta, abstractmethod

from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_v1_5


class PublicKeyCipher(object):
    __metaclass__ = ABCMeta

    algo = None

    @abstractmethod
    def encrypt(self, session_key):
        return NotImplemented

    @abstractmethod
    def verify(self, hash, signature):
        return NotImplemented

    @property
    def parameters(self):
        return NotImplemented


class DSAPublicKeyCipher(PublicKeyCipher):
    algo = 'dsa'

    def __init__(self, public_key_info):
        public_key = public_key_info['public_key'].native
        params = public_key_info['algorithm']['parameters'].native
        key = DSA.construct.construct((public_key, params['g'], params['p'], params['q']))
        self._cipher = PKCS1_v1_5.new(key)

    def encrypt(self, session_key):
        return self._cipher.encrypt(session_key)

    def verify(self, hash, signature):
        return self._cipher.verify(hash, signature)

    @property
    def parameters(self):
        # The subject DSA public key will use the same DSA parameters as the
        # certificate issuer.
        return None


class RSAPublicKeyCipher(PublicKeyCipher):
    algo = 'rsa'

    def __init__(self, public_key_info):
        rsa = public_key_info['public_key'].native
        key = RSA.construct((rsa['modulus'], rsa['public_exponent']))
        self._cipher = PKCS1_v1_5.new(key)

    def encrypt(self, session_key):
        return self._cipher.encrypt(session_key)

    def verify(self, hash, signature):
        return self._cipher.verify(hash, signature)

    @property
    def parameters(self):
        # AlgorithmIdentifier parameters is always NULL
        return None

