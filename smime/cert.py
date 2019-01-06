# coding: utf-8

"""X509 Certificate API."""

from __future__ import unicode_literals

import hashlib

from asn1crypto import cms
from asn1crypto import pem
from asn1crypto import x509

from .pubkey import RSAPublicKeyCipher


class CertificateError(Exception):
    """Certificate has errors."""

    pass


class Certificate(object):
    """X509 certificates."""

    PEM_MARKERS = ("CERTIFICATE",)

    def __init__(self, der_string):
        """Initialize from a DER string.

        Args:
            der_string: a binary string containing the DER-encoded
                certificate.
        """
        self._cert = x509.Certificate.load(der_string)

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.is_identical_to(other)
        else:
            return NotImplemented

    def __ne__(self, other):
        are_equal = self.__eq__(other)

        if are_equal is NotImplemented:
            return NotImplemented
        else:
            return not are_equal

    def __hash__(self):
        return hash(self.fingerprint())

    def __str__(self):
        return self._cert.debug()

    @classmethod
    def from_pem(cls, pem_string):
        """Read a single PEM-encoded certificate from a string.

        Args:
            pem_string: the certificate string.

        Returns:
            a Certificate object.
        """
        _, _, der_bytes = pem.unarmor(pem_string)
        return cls.from_der(der_bytes)

    @classmethod
    def from_der(cls, der_string):
        """Read a single DER-encoded certificate from a string.

        This is just an alias to __init__ to match from_pem().

        Args:
            der_string: the certificate string.

        Returns:
            a Certificate object.
        """
        return cls(der_string)

    @classmethod
    def from_pem_file(cls, pem_file):
        """Read a single PEM-encoded certificate from a file.

        Args:
            pem_file: the certificate file.

        Returns:
            a Certificate object
        """
        with open(pem_file, "rb") as pem_cert_file:
            return cls.from_pem(pem_cert_file.read())

    @classmethod
    def from_der_file(cls, der_file):
        """Read a single DER-encoded certificate from a file.

        Args:
            der_file: the certificate file.

        Returns:
            a Certificate object.
        """
        with open(der_file, "rb") as der_cert_file:
            return cls.from_der(der_cert_file.read())

    def to_der(self):
        """Get the DER-encoding of the certificate."""
        return self._cert.dump()

    def to_pem(self):
        """Get the PEM-encoding of the certificate."""
        return pem.armor(self.PEM_MARKERS[0], self.to_der())

    def is_identical_to(self, other_cert):
        """Returns True if this certificate is identical to |other_cert|."""
        return self.to_der() == other_cert.to_der()

    def to_asn1(self):
        """Get a copy of the ASN.1 representation of the certificate."""
        return x509.Certificate.load(self._cert.dump())

    @property
    def self_signed(self):
        """Is self signed?

        Returns:
            True or False.
        """
        return (
            self._cert["tbs_certificate"]["issuer"]
            == self._cert["tbs_certificate"]["subject"]
        )

    def fingerprint(self, hashfunc="sha1"):
        """Get the certificate fingerprint.

        Args:
            hashfunc: name of a hash function. Algorithms always present are
                'md5', 'sha1', 'sha224', 'sha256', 'sha384', and 'sha512'.
        Returns:
            a (binary) hash digest of the DER encoding.
        """
        h = hashlib.new(hashfunc)
        h.update(self._cert.dump())
        return h.digest()

    def key_hash(self, hashfunc="sha1"):
        """Get the certificate's public key hash.

        Args:
            hashfunc: name of a hash function. Algorithms always present are
                'md5', 'sha1', 'sha224', 'sha256', 'sha384', and 'sha512'.
        Returns:
            a (binary) hash digest of the public key.
        """
        h = hashlib.new(hashfunc)
        h.update(self._cert["tbs_certificate"]["subject_public_key_info"].dump())
        return h.digest()

    def _get_public_key_cipher(self):
        """
        :return:
            The PublicKey object for this certificate
        """
        algorithms = {RSAPublicKeyCipher.algo: RSAPublicKeyCipher}
        public_key_info = self._cert.public_key
        algorithm = public_key_info.algorithm
        if algorithm not in algorithms:
            return None
        t = algorithms[algorithm]
        return t(public_key_info)

    def recipient_info(self, session_key):
        cipher = self._get_public_key_cipher()
        if cipher is None:
            return None
        encrypted_key = cipher.encrypt(session_key)
        tbs_cert = self._cert["tbs_certificate"]
        # TODO: use subject_key_identifier when available
        return cms.RecipientInfo(
            name="ktri",
            value={
                "version": "v0",
                "rid": cms.RecipientIdentifier(
                    name="issuer_and_serial_number",
                    value={
                        "issuer": tbs_cert["issuer"],
                        "serial_number": tbs_cert["serial_number"],
                    },
                ),
                "key_encryption_algorithm": {
                    "algorithm": cipher.algo,
                    "parameters": cipher.parameters,
                },
                "encrypted_key": encrypted_key,
            },
        )


def certs_from_pem(pem_string):
    """Read multiple PEM-encoded certificates from a string.

    Args:
        pem_string: the certificate string.

    Yields:
        Certificate objects.
    """
    for _, _, der_bytes in pem.unarmor(pem_string, multiple=True):
        yield Certificate.from_der(der_bytes)


def certs_from_pem_file(pem_file):
    """Read multiple PEM-encoded certificates from a file.

    Args:
        pem_file: the certificate file.

    Yields:
        Certificate objects.
    """
    with open(pem_file, "rb") as certs_pem_file:
        return certs_from_pem(certs_pem_file.read())
