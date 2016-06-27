from ct.crypto.asn1 import oid

from Crypto.Cipher import AES

from abc import ABCMeta, abstractmethod

ID_AES128_CBC = oid.ObjectIdentifier('2.16.840.1.101.3.4.1.2')
ID_AES192_CBC = oid.ObjectIdentifier('2.16.840.1.101.3.4.1.22')
ID_AES256_CBC = oid.ObjectIdentifier('2.16.840.1.101.3.4.1.42')


class Algorithm():
    __metaclass__ = ABCMeta

    _cipher = None

    def __init__(self, key, **kwargs):
        self._cipher = self.new(key, **kwargs)

    @abstractmethod
    def new(self, **kwargs):
        return NotImplemented

    @abstractmethod
    def encrypt(self, data):
        return NotImplemented


class AES_CBC(Algorithm):
    block_size = 16

    def __init__(self, key, iv):
        super(AES_CBC, self).__init__(key, iv=iv)

    def new(self, session_key, iv=None):
        return AES.new(session_key, AES.MODE_CBC, iv)

    def encrypt(cls, data):
        padded_data = cls._pad(data, cls.block_size)
        return cls._cipher.encrypt(padded_data)

    def _pad(cls, s, block_size):
        n = block_size - len(s) % block_size
        return s + n * chr(n)


class AES128_CBC(AES_CBC):
    oid = ID_AES128_CBC
    key_size = 16


class AES192_CBC(AES_CBC):
    oid = ID_AES192_CBC
    key_size = 24


class AES256_CBC(AES_CBC):
    oid = ID_AES256_CBC
    key_size = 32
