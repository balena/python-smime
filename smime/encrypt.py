# Refer to RFC3565

import sys
import base64
import Crypto.Random.OSRNG as RNG
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from email import message_from_string
from email.mime.text import MIMEText

from ct.crypto import cert
from ct.crypto.asn1 import oid, types
from ct.crypto.asn1 import cms
from ct.crypto.asn1 import cms_common

from abc import ABCMeta, abstractproperty, abstractmethod

if sys.version_info > (3,):
    long = int

ID_AES256_CBC = oid.ObjectIdentifier('2.16.840.1.101.3.4.1.42')


class RSAPublicKey(types.Sequence):
    components = (
        (types.Component('modulus', types.Integer)),
        (types.Component('publicExponent', types.Integer))
        )


def __get_issuer_and_serial_number(x509_cert):
    tbsCertificate = x509_cert['tbsCertificate']
    return cms_common.IssuerAndSerialNumber({
        'issuer': tbsCertificate['issuer'],
        'serialNumber': tbsCertificate['serialNumber']
    })


def __get_enveloped_data(x509_cert, encrypted_key, iv, encrypted_content):
    return cms.ContentInfo({
        'contentType': oid.ID_ENVELOPED_DATA,
        'content': cms.EnvelopedData({
            'version': cms_common.CMSVersion('v0'),
            'recipientInfos': cms_common.RecipientInfos([
                cms_common.RecipientInfo({
                    'ktri': cms_common.KeyTransRecipientInfo({
                        'version': cms_common.CMSVersion('v0'),
                        'rid': cms_common.RecipientIdentifier({
                            'issuerAndSerialNumber': __get_issuer_and_serial_number(x509_cert)
                        }),
                        'keyEncryptionAlgorithm': cms_common.KeyEncryptionAlgorithmIdentifier({
                            'algorithm': oid.RSA_ENCRYPTION,
                            'parameters': types.Null(False)
                        }),
                        'encryptedKey':  cms_common.EncryptedKey(encrypted_key)
                    })
                })
            ]),
            'encryptedContentInfo': cms_common.EncryptedContentInfo({
                'contentType': oid.ID_DATA,
                'contentEncryptionAlgorithm': cms_common.ContentEncryptionAlgorithmIdentifier({
                    'algorithm': ID_AES256_CBC,
                    'parameters': types.OctetString(iv)
                }),
                'encryptedContent': cms_common.EncryptedContent(encrypted_content)
            })
        })
    })


def __encode_in_base64(stream):
    columns = 64
    result = []
    stream = base64.b64encode(stream)
    while len(stream) > 0:
        chunk = stream[:columns]
        stream = stream[columns:]
        result.append(chunk)
    return '\n'.join(result)


def __bin2bytearray(s):
    assert len(s) % 8 == 0
    result = []
    while s:
        byte = int(''.join([str(x) for x in s[:8]]), 2)
        result.append(chr(byte))
        s = s[8:]
    return ''.join(result)


def __get_public_rsa_key(x509_cert):
    return __bin2bytearray(tuple(x509_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'].value))


def __pad(s, block_size):
    n = block_size - len(s) % block_size
    return s + n * chr(n)


def __load_pubkey(pubkey):
    x509_certs = cert.certs_from_pem(pubkey)
    x509_cert = x509_certs.next()._asn1_cert
    der = __get_public_rsa_key(x509_cert)
    key = RSA.importKey(der)
    cipher = PKCS1_v1_5.new(key)
    return x509_cert, cipher


class Algorithm():
    __metaclass__ = ABCMeta

    block_size = None

    @abstractproperty
    def key_size(self):
        return NotImplemented

    @abstractmethod
    def new(self, session_key, iv=None):
        return NotImplemented


class AES_CBC(Algorithm):
    block_size = 16

    @classmethod
    def new(self, session_key, iv):
        return AES.new(session_key, AES.MODE_CBC, iv)


class AES_128_CBC(AES_CBC):
    def __init__(self):
        self._key_size = 16

    @property
    def key_size(self):
        return self._key_size


class AES_192_CBC(AES_CBC):
    def __init__(self):
        self._key_size = 24

    @property
    def key_size(self):
        return self._key_size


class AES_256_CBC(AES_CBC):
    def __init__(self):
        self._key_size = 32

    @property
    def key_size(self):
        return self._key_size


def __encrypt_internal(rsa, algo, content, session_key, iv):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """
    encrypted_key = rsa.encrypt(session_key)

    enc = algo.new(session_key, iv)
    encrypted_content = enc.encrypt(__pad(content, algo.block_size))

    return encrypted_key, encrypted_content


def encrypt(message, pubkey):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """
    algo = AES_256_CBC()  # we support only AES-256-CBC by now

    # Get the message content
    msg = message_from_string(message)
    content = msg.get_payload()

    x509_cert, rsa = __load_pubkey(pubkey)

    session_key = RNG.new().read(algo.key_size)
    iv = RNG.new().read(algo.block_size)

    encrypted_key, encrypted_content = __encrypt_internal(rsa, algo, content, session_key, iv)

    # Encode the content
    enveloped_data = __get_enveloped_data(x509_cert, encrypted_key, iv, encrypted_content)
    encoded_content = __encode_in_base64(enveloped_data.encode())

    # Create the resulting message
    result_msg = MIMEText(encoded_content)
    overrides = {
        'MIME-Version': '1.0',
        'Content-Type': 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m',
        'Content-Transfer-Encoding': 'base64',
        'Content-Disposition': 'attachment; filename=smime.p7m'
    }

    for name, value in msg.items():
        if name in overrides.keys():
            continue
        result_msg.add_header(name, value)

    for name, value in overrides.items():
        if result_msg.has_key(name):
            result_msg.replace_header(name, value)
        else:
            result_msg[name] = value

    return result_msg.as_string()
