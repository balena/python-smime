# Refer to RFC3565
# coding: utf-8

from __future__ import unicode_literals

from base64 import b64encode
from email import message_from_string
from email.mime.text import MIMEText

from .cert import certs_from_pem
from .block import get_cipher
from .print_util import wrap_lines

from asn1crypto import cms


def __iterate_recipient_infos(certs, session_key):
    if isinstance(certs, (tuple, list)):
        for cert_file in certs:
            for cert in certs_from_pem(cert_file):
                recipient_info = cert.recipient_info(session_key)
                yield recipient_info
    else:
        for cert in certs_from_pem(certs):
            recipient_info = cert.recipient_info(session_key)
            yield recipient_info


def encrypt(message, certs, algorithm='aes256'):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822, and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: string containing the new encrypted message.
    """
    # Get the chosen block cipher
    block_cipher = get_cipher(algorithm)
    if block_cipher == None:
        raise ValueError('Unknown block algorithm')

    # Get the message content
    msg = message_from_string(message)
    to_encode = MIMEText(msg.get_payload())
    content = to_encode.as_string()

    # Generate the recipient infos
    recipient_infos = []
    for recipient_info in __iterate_recipient_infos(certs, block_cipher.session_key):
        if recipient_info == None:
            raise ValueError('Unknown public-key algorithm')
        recipient_infos.append(recipient_info)

    # Encode the content
    encrypted_content_info = block_cipher.encrypt(content)

    # Build the enveloped data and encode in base64
    enveloped_data = cms.ContentInfo({
        'content_type': 'enveloped_data',
        'content': {
            'version': 'v0',
            'recipient_infos': recipient_infos,
            'encrypted_content_info': encrypted_content_info
        }
    })
    encoded_content = '\n'.join(wrap_lines(b64encode(enveloped_data.dump()), 64))

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
