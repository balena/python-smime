# coding: utf-8

from __future__ import unicode_literals

from Crypto import Cipher
import Crypto.Random.OSRNG as RNG

from abc import ABCMeta, abstractmethod


class BlockCipher():
    __metaclass__ = ABCMeta

    @abstractmethod
    def encrypt(self, data):
        return NotImplemented

    @property
    def session_key(self):
        return NotImplemented

    @property
    def parameters(self):
        return NotImplemented


class AES(BlockCipher):
    algorithm = None
    key_size = None
    block_size = 16

    def __init__(self, algorithm, mode, key_size):
        self.algorithm = algorithm
        self.mode = mode
        self.key_size = key_size
        self._session_key = RNG.new().read(self.key_size)
        self._iv = RNG.new().read(self.block_size)
        self._cipher = Cipher.AES.new(self._session_key, mode, self._iv)

    @property
    def session_key(self):
        return self._session_key

    def encrypt(self, data):
        padded_data = self._pad(data, self.block_size)
        encrypted_content = self._cipher.encrypt(padded_data)
        return {
            'content_type': 'data',
            'content_encryption_algorithm': {
                'algorithm': self.algorithm,
                'parameters': self._iv
            },
            'encrypted_content': encrypted_content
        }

    @staticmethod
    def _pad(s, block_size):
        n = block_size - len(s) % block_size
        return s + n * chr(n)

    @property
    def parameters(self):
        return self._iv


def get_cipher(algorithm):
    algorithms = {
        'aes128_cbc': (AES, (Cipher.AES.MODE_CBC, 16)),
        'aes192_cbc': (AES, (Cipher.AES.MODE_CBC, 24)),
        'aes256_cbc': (AES, (Cipher.AES.MODE_CBC, 32)),
    }
    if algorithm in algorithms:
        cipher, parameters = algorithms[algorithm]
        return cipher(algorithm, *parameters)
    else:
        return None