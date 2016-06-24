# Refer to RFC3565

import sys
import base64
import Crypto.Random.OSRNG as RNG
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from email import message_from_string
from email.mime.text import MIMEText

from ct.crypto import cert
from ct.crypto.asn1 import oid, types
from ct.crypto.asn1 import cms
from ct.crypto.asn1 import cms_common

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
    substrate = __bin2bytearray(tuple(x509_cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'].value))
    content = RSAPublicKey.decode(substrate)
    return long(content['modulus'].value), long(content['publicExponent'].value)


def __pad1(s, block_size):
    n = block_size - len(s) % block_size
    return s + n * chr(n)


def encrypt(message, pubkey):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """
    algorithm = AES  # we support only AES-256-CBC by now
    key_size = 32
    mode = AES.MODE_CBC

    # Get the message content
    msg = message_from_string(message)
    content = msg.get_payload()

    # Read the pubkey
    x509_certs = cert.certs_from_pem(pubkey)
    x509_cert = x509_certs.next()._asn1_cert
    key = __get_public_rsa_key(x509_cert)
    block_size = algorithm.block_size
    rsa = RSA.construct(key)

    session_key = RNG.new().read(key_size)
    iv = RNG.new().read(block_size)
    aes = algorithm.new(session_key, mode, iv)
    encrypted_content = aes.encrypt(__pad1(content, block_size))
    encrypted_key = rsa.encrypt(session_key, len(session_key))[0]

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
