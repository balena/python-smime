# _*_ coding: utf-8 _*_
"""Refer to RFC3565"""
from base64 import b64encode
from copy import deepcopy
from email import message_from_string
from email.mime.text import MIMEText

import six
from asn1crypto import cms

from .block import get_cipher
from .cert import certs_from_pem
from .print_util import wrap_lines


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


def encrypt(message, certs, algorithm="aes256_cbc"):
    """
    Takes the contents of the message parameter, formatted as in RFC 2822 (type str or message), and encrypts them,
    so that they can only be read by the intended recipient specified by pubkey.
    :return: the new encrypted message (type str or message, as per input).
    """
    # Get the chosen block cipher
    block_cipher = get_cipher(algorithm)
    if block_cipher is None:
        raise ValueError("Unknown block algorithm")

    # Get the message content. This could be a string, or a message object
    passed_as_str = isinstance(message, six.string_types)

    if passed_as_str:
        message = message_from_string(message)
    # Extract the message payload without conversion, & the outermost MIME header / Content headers. This allows
    # the MIME content to be rendered for any outermost MIME type incl. multipart
    copied_msg = deepcopy(message)

    headers = {}
    # bellows headers are wiped from cloned and would be added in newly created message instance
    for hdr_name in ("Subject", "To", "BCC", "CC", "From"):
        values = copied_msg.get_all(hdr_name)
        if values:
            del copied_msg[hdr_name]
            headers[hdr_name] = values

    content = copied_msg.as_string()
    recipient_infos = []

    for recipient_info in __iterate_recipient_infos(certs, block_cipher.session_key):
        if recipient_info is None:
            raise ValueError("Unknown public-key algorithm")
        recipient_infos.append(recipient_info)

    # Encode the content
    encrypted_content_info = block_cipher.encrypt(content)

    # Build the enveloped data and encode in base64
    enveloped_data = cms.ContentInfo(
        {
            u"content_type": u"enveloped_data",
            u"content": {
                u"version": u"v0",
                u"recipient_infos": recipient_infos,
                u"encrypted_content_info": encrypted_content_info,
            },
        }
    )
    encoded_content = "\n".join(wrap_lines(b64encode(enveloped_data.dump()), 64))

    # Create the resulting message
    result_msg = MIMEText(encoded_content)
    overrides = (
        ("MIME-Version", "1.0"),
        (
            "Content-Type",
            "application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m",
        ),
        ("Content-Transfer-Encoding", "base64"),
        ("Content-Disposition", "attachment; filename=smime.p7m"),
    )

    for name, value in list(copied_msg.items()):
        if name in [x for x, _ in overrides]:
            continue
        result_msg.add_header(name, value)

    for name, value in overrides:
        if name in result_msg:
            del result_msg[name]
        result_msg[name] = value

    # adds header
    for hrd, values in six.iteritems(headers):
        for val in values:
            result_msg.add_header(hrd, val)

    # return the same type as was passed in
    if passed_as_str:
        return result_msg.as_string()
    else:
        return result_msg
