# coding: utf-8

from __future__ import unicode_literals

import os
from abc import ABCMeta
from abc import abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


class BlockCipher:
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
        self._session_key = os.urandom(self.key_size)
        self._iv = os.urandom(self.block_size)
        algorithm = algorithms.AES(self._session_key)
        mode = mode(self._iv)
        backend = default_backend()
        self._encryptor = Cipher(algorithm, mode, backend=backend).encryptor()

    @property
    def session_key(self):
        return self._session_key

    def encrypt(self, data):
        padded_data = self._pad(data, self.block_size)
        encrypted_content = (
            self._encryptor.update(padded_data.encode("utf-8"))
            + self._encryptor.finalize()
        )
        return {
            "content_type": "data",
            "content_encryption_algorithm": {
                "algorithm": self.algorithm,
                "parameters": self._iv,
            },
            "encrypted_content": encrypted_content,
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
        "aes128_cbc": (AES, (modes.CBC, 16)),
        "aes192_cbc": (AES, (modes.CBC, 24)),
        "aes256_cbc": (AES, (modes.CBC, 32)),
    }
    if algorithm in algorithms:
        cipher, parameters = algorithms[algorithm]
        return cipher(algorithm, *parameters)
    else:
        return None
