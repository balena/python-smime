# Refer to RFC3565

import base64
import Crypto.Random.OSRNG as RNG
from email import message_from_string
from email.mime.text import MIMEText

from .rsa import RSAPublicKey
from .aes import AES128_CBC, AES192_CBC, AES256_CBC

from smime.crypto.asn1 import oid, types
from smime.crypto.asn1 import cms
from smime.crypto.asn1 import cms_common


def __get_issuer_and_serial_number(x509_cert):
    tbsCertificate = x509_cert['tbsCertificate']
    return cms_common.IssuerAndSerialNumber({
        'issuer': tbsCertificate['issuer'],
        'serialNumber': tbsCertificate['serialNumber']
    })


def __get_enveloped_data(pubkey_cipher, sym_cipher, x509_cert, encrypted_key, iv, encrypted_content):
    return cms.ContentInfo({
        'contentType': oid.ID_ENVELOPED_DATA,
        'content': cms.EnvelopedData({
            'version': cms_common.CMSVersion('v0'),
            'recipientInfos': cms_common.RecipientInfos([
                cms_common.RecipientInfo({
                    'ktri': cms_common.KeyTransRecipientInfo({
                        'version': cms_common.CMSVersion('v0'),
                        'rid': cms_common.RecipientIdentifier({
                            'issuerAndSerialNumber':
                                __get_issuer_and_serial_number(x509_cert)
                        }),
                        'keyEncryptionAlgorithm':
                            cms_common.KeyEncryptionAlgorithmIdentifier({
                                'algorithm': pubkey_cipher.oid,
                                'parameters': types.Null(False)
                            }),
                        'encryptedKey':  cms_common.EncryptedKey(encrypted_key)
                    })
                })
            ]),
            'encryptedContentInfo': cms_common.EncryptedContentInfo({
                'contentType': oid.ID_DATA,
                'contentEncryptionAlgorithm': cms_common.ContentEncryptionAlgorithmIdentifier({
                    'algorithm': sym_cipher.oid,
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


def __encrypt_internal(rsa, algo, content, session_key):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """
    return rsa.encrypt(session_key), algo.encrypt(content)


def encrypt(message, pubkey, algorithm='aes256'):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """

    if algorithm == 'aes256':
        Algo = AES256_CBC
    elif algorithm == 'aes192':
        Algo = AES192_CBC
    elif algorithm == 'aes128':
        Algo = AES128_CBC
    else:
        raise ValueError('Unknown algorithm')

    # Get the message content
    msg = message_from_string(message)
    to_encode = MIMEText(msg.get_payload())
    content = to_encode.as_string()

    pubkey_cipher = RSAPublicKey(pubkey)

    session_key = RNG.new().read(Algo.key_size)
    iv = RNG.new().read(Algo.block_size)
    sym_cipher = Algo(session_key, iv)

    encrypted_key = pubkey_cipher.encrypt(session_key)
    encrypted_content = sym_cipher.encrypt(content)

    # Encode the content
    enveloped_data = __get_enveloped_data(pubkey_cipher, sym_cipher,
            pubkey_cipher.get_cert(), encrypted_key, iv, encrypted_content)
    encoded_content = __encode_in_base64(enveloped_data.encode())

    # Create the resulting message
    result_msg = MIMEText(encoded_content)
    overrides = (
        ('MIME-Version', '1.0'),
        ('Content-Type', 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'),
        ('Content-Transfer-Encoding', 'base64'),
        ('Content-Disposition', 'attachment; filename=smime.p7m')
    )

    for name, value in list(msg.items()):
        if name in [x for x, _ in  overrides]:
            continue
        result_msg.add_header(name, value)

    for name, value in overrides:
        if name in result_msg:
            del result_msg[name]
        result_msg[name] = value

    return result_msg.as_string()
