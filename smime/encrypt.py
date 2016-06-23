# Refer to RFC3565

import base64
import Crypto.Random.OSRNG as RNG
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from email import message_from_string
from email.mime.text import MIMEText
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import tag, univ

from pyasn1_modules import rfc2437
from pyasn1_modules.rfc2315 import Name, EncryptedContent

import rfc4055
from rfc5652 import EnvelopedData, RecipientInfos, RecipientInfo, IssuerAndSerialNumber, CMSVersion, \
    KeyTransRecipientInfo, RecipientIdentifier, KeyEncryptionAlgorithmIdentifier, EncryptedKey, EncryptedContentInfo,\
    ContentEncryptionAlgorithmIdentifier, id_data
from x509 import parse


id_aes256_CBC = univ.ObjectIdentifier('2.16.840.1.101.3.4.1.42')


def __instance(klazz, *args, **kwargs):
    object = klazz()
    for k, v in enumerate(args):
        object[k] = v
    for k, v in kwargs.iteritems():
        object[k] = v
    return object


def __get_issuer_and_serial_number(cert):
    tbsCertificate = cert['tbsCertificate']
    issuer = tbsCertificate['issuer']
    rdnSequence = issuer['']

    name = Name()
    name[''] = rdnSequence
    return __instance(
        IssuerAndSerialNumber,
        issuer=name,
        serialNumber=tbsCertificate['serialNumber']
    )


def __get_enveloped_data(cert, encrypted_key, iv, encrypted_content):
    content = EncryptedContent(encrypted_content)\
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    return __instance(
        EnvelopedData,
        version=CMSVersion('v0'),
        recipientInfos=__instance(
            RecipientInfos,
            __instance(
                RecipientInfo,
                ktri=__instance(
                    KeyTransRecipientInfo,
                    version='v0',
                    rid=__instance(
                        RecipientIdentifier,
                        issuerAndSerialNumber=__get_issuer_and_serial_number(cert)
                    ),
                    keyEncryptionAlgorithm=__instance(
                        KeyEncryptionAlgorithmIdentifier,
                        algorithm=rfc2437.rsaEncryption,
                        parameters=univ.Null()
                    ),
                    encryptedKey=EncryptedKey(encrypted_key)
                )
            )
        ),
        encryptedContentInfo=__instance(
            EncryptedContentInfo,
            contentType=id_data,
            contentEncryptionAlgorithm=__instance(
                ContentEncryptionAlgorithmIdentifier,
                algorithm=id_aes256_CBC,
                parameters=univ.OctetString(iv)
            ),
            encryptedContent=content
        )
    )

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


def __get_public_rsa_key(cert):
    substrate = __bin2bytearray(tuple(cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']))
    content, _ = decoder.decode(substrate, asn1Spec=rfc4055.RSAPublicKey())
    return (long(content['modulus']), long(content['publicExponent']))


def __pad(s, block_size):
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
    cert, _ = parse(pubkey)
    key = __get_public_rsa_key(cert)
    block_size = algorithm.block_size
    rsa = RSA.construct(key)

    session_key = RNG.new().read(key_size)
    iv = RNG.new().read(block_size)
    aes = algorithm.new(session_key, mode, iv)
    encrypted_content = aes.encrypt(__pad(content, block_size))
    encrypted_key = rsa.encrypt(session_key, len(session_key))[0]

    # Encode the content
    enveloped_data = __get_enveloped_data(cert, encrypted_key, iv, encrypted_content)
    encoded_content = __encode_in_base64(encoder.encode(enveloped_data))

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
