=====================
Python S/MIME Toolkit
=====================

This library implements a S/MIME handler. In this first version, it can only
encrypt S/MIME messages using a public RSA key, in AES128-CBC, AES192-CBC or
AES256-CBC modes.

The ASN.1 implementation does not depend on pyasn1, as it showed too broken for
creating and reading CMS (Cryptographic Message Syntax). Instead, the
`Google's certificate transparency project`_ was used in this project.

This implementation uses pycrypto instead of OpenSSL, so everything is 'pure
python'.


Requirements
------------

* Python 2.7 or Python 3.3
* pycrypto


Example
-------

The code below loads Alice's public key in PEM format and uses it to encrypt
the e-mail in S/MIME format::

    import sys
    import smime

    message = [
        'To: "Alice" <alice@foo.com>',
        'From: "Bob" <bob@bar.com>',
        'Subject: A message from python',
        '',
        'Now you see me.'
    ]

    with open('alice-public-key.pem', 'rb') in pem
        print(smime.encrypt('\n'.join(message), pem.read()))

Output::

    To: "Alice" <alice@foo.com>
    From: "Bob" <bob@bar.com>
    Subject: A message from python
    MIME-Version: 1.0
    Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m
    Content-Transfer-Encoding: base64
    Content-Disposition: attachment; filename=smime.p7m

    <base64-enveloped-data>

The same can be decrypted using OpenSSL from the command line::

    $ openssl smime -decrypt -in smime.p7m -inkey alice-private-key.pem


License
=======

This software is licensed under the Apache License 2.0. See the LICENSE file in
the top distribution directory for the full license text.


Versioning
==========

This software follows `Semantic Versioning`_


.. _Google's certificate transparency project: https://www.certificate-transparency.org/)
.. _Semantic Versioning: http://semver.org/
