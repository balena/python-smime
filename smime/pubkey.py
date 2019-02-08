from __future__ import unicode_literals

from abc import ABCMeta
from abc import abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class PublicKeyCipher(object):
    __metaclass__ = ABCMeta

    algo = None

    @abstractmethod
    def encrypt(self, session_key):
        return NotImplemented

    @property
    def parameters(self):
        return NotImplemented


class RSAPublicKeyCipher(PublicKeyCipher):
    algo = "rsa"

    def __init__(self, public_key_info):
        rsaparams = public_key_info["public_key"].native
        key = rsa.RSAPublicNumbers(rsaparams["public_exponent"], rsaparams["modulus"])
        backend = default_backend()
        self._cipher = key.public_key(backend)
        self._padding = padding.PKCS1v15()

    def encrypt(self, session_key):
        return self._cipher.encrypt(session_key, self._padding)

    @property
    def parameters(self):
        # AlgorithmIdentifier parameters is always NULL
        return None
