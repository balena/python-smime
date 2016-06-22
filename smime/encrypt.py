# Refer to RFC3565

import base64
from email import message_from_string
from email.mime.text import MIMEText
from x509 import parse, getkey
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import Crypto.Random.OSRNG.posix as RNG
from pyasn1.type import univ
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc2459, rfc2437
from rfc3369 import EnvelopedData, RecipientInfos, RecipientInfo, IssuerAndSerialNumber, Name, RDNSequence,\
    RelativeDistinguishedName, AttributeTypeAndValue, CMSVersion, KeyTransRecipientInfo, RecipientIdentifier,\
    KeyEncryptionAlgorithmIdentifier, EncryptedKey, EncryptedContentInfo, ContentEncryptionAlgorithmIdentifier, \
    EncryptedContent, id_data


id_aes256_CBC = univ.ObjectIdentifier('2.16.840.1.101.3.4.1.42')

def __get_issuer_and_serial_number(cert):
    # TODO
    issuerAndSerialNumber = IssuerAndSerialNumber()
    issuerAndSerialNumber['issuer'] = Name()
    issuerAndSerialNumber['issuer'][''] = RDNSequence()
    issuerAndSerialNumber['issuer'][''][0] = RelativeDistinguishedName()
    issuerAndSerialNumber['issuer'][''][0][0] = AttributeTypeAndValue()
    issuerAndSerialNumber['issuer'][''][0][0]['type'] = rfc2459.id_at_countryName
    issuerAndSerialNumber['issuer'][''][0][0]['value'] = rfc2459.X520countryName('GB')
    return issuerAndSerialNumber

def __get_enveloped_data(cert, encrypted_key, iv, encrypted_content):
    envelopedData = EnvelopedData()
    envelopedData['version'] = CMSVersion('v0')

    recipientInfo = RecipientInfo()

    ktri = KeyTransRecipientInfo()
    ktri['version'] = CMSVersion('v0')

    rid = RecipientInfo()
    rid['issuerAndSerialNumber'] = __get_issuer_and_serial_number(cert)

    ktri['rid'] = RecipientIdentifier()

    keyEncryptionAlgorithm = KeyEncryptionAlgorithmIdentifier()
    keyEncryptionAlgorithm['algorithm'] = rfc2437.rsaEncryption
    keyEncryptionAlgorithm['parameters'] = univ.Null

    ktri['keyEncryptionAlgorithm'] = keyEncryptionAlgorithm
    ktri['encryptedKey'] = EncryptedKey(encrypted_key)

    recipientInfo['ktri'] = ktri

    recipientInfos = RecipientInfos()
    recipientInfos[0] = recipientInfo

    envelopedData['recipientInfos'] = recipientInfos

    contentEncryptionAlgorithm = ContentEncryptionAlgorithmIdentifier()
    contentEncryptionAlgorithm['algorithm'] = id_aes256_CBC
    contentEncryptionAlgorithm['parameters'] = univ.OctetString(iv)

    encryptedContentInfo = EncryptedContentInfo()
    encryptedContentInfo['contentType'] = id_data
    encryptedContentInfo['contentEncryptionAlgorithm'] = contentEncryptionAlgorithm
    encryptedContentInfo['encryptedContent'] = EncryptedContent(encrypted_content)

    envelopedData['encryptedContentInfo'] = encryptedContentInfo
    return envelopedData


def __encode_in_base64(stream):
    columns = 64
    result = []
    while len(stream) > 0:
        chunk = stream[:columns]
        stream = stream[columns:]
        result.append(chunk)
    return '\n'.join(result)


def encrypt(message, pubkey):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """
    algorithm = AES      # we support only AES-256-CBC by now
    key_size = 32
    mode = AES.MODE_CBC

    # Get the message content
    msg = message_from_string(message)
    content = msg.get_payload()

    # Read the pubkey
    cert, _ = parse(pubkey)
    key = getkey(cert)
    block_size = algorithm.block_size
    rsa = RSA.construct(key)

    session_key = RNG.new().read(block_size)
    iv = RNG.new().read(key_size)
    aes = algorithm.new(session_key, mode, iv)
    encrypted_content = aes.encrypt(content)
    encrypted_key = rsa.encrypt(session_key, len(session_key))

    # Encode the content
    enveloped_data = __get_enveloped_data(cert, encrypted_key, iv, encrypted_content)
    encoded_content = __encode_in_base64(encoder.encode(enveloped_data))

    # Create the resulting message
    result_msg = MIMEText(encoded_content)
    for name, value in msg:
        result_msg[name] = value
    result_msg['Content-Type'] = 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'
    result_msg['Content-Transfer-Encoding'] = 'base64'
    result_msg['Content-Disposition'] = 'attachment; filename=smime.p7m'

    return result_msg.as_string()