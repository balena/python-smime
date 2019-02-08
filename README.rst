=====================
Python S/MIME Toolkit
=====================

.. warning::
    This package is pure fork version from https://github.com/balena/python-smime with immediate release version which contains some necessary refactoring.
    All credits go to original Author(s).
    Publisher of this fork version (Md Nazrul Islam<email2nazrul@gmail.com>) doest not reserve any Copyright rights.

This library implements a S/MIME handler. It supports only S/MIME messages
encryption using a public RSA key, in AES128-CBC, AES192-CBC or AES256-CBC
modes.

The ASN.1 implementation does not depend on pyasn1, as it showed too broken for
creating and reading CMS (Cryptographic Message Syntax). Instead, the
`asn1crypto`_ was used in this project.

This implementation does not use the deprecated `pycrypto` anymore; instead it
was switched to the more modern `cryptography` library. It is not 'pure python'
anymore (because of the latter dependency), but at least works.


Requirements
------------

* Python 2.7 or Python 3.5+
* cryptography
* asn1crypto


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

    with open('alice-public-key.pem', 'rb') as pem:
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

OpenSSL expects that the `smime.p7m` file above should be in DER or PEM format.
The latter should be enclosed in `-----BEGIN PKCS7-----` and `-----END
PKCS7-----` and the content should be in base64 encoding, just like the output
of the command above. Example::

    -----BEGIN PKCS7-----
    MIIBdgYJKoZIhvcNAQcDoIIBZzCCAWMCAQAxgb4wgbsCAQAwJjASMRAwDgYDVQQD
    EwdDYXJsUlNBAhBGNGvHgABWvBHTbi7EELOwMAsGCSqGSIb3DQEBAQSBgCVAQwNg
    LmJ5ESYxOM1YbOLz2gvzWY1Fk+LZZiylYe7+o1/e/MjtzNwhnu+8vziFwHbXEH1Y
    jndIbUxiLyXb3omtNDunRICQin5bdo6BI7oE0MufUSqMjk0YUk8UQeNCiUfK89PR
    RfDclb1/sM3XZ7mUJa2OzpnuQIWec3MuJ3k4MIGcBgkqhkiG9w0BBwEwHQYJYIZI
    AWUDBAEqBBCVZVOt2lxSzmd+Ti1M372xgHDR0+ToLk1MJeTTtmJdnnNNH6631PN0
    i3NJeJBKDDs4onI8xywqFtJP0of6GPoTGV/7D2vkgO2+jhCBTrzjYczbdOhh6Z5X
    o0i/81NPSoaLhrfwKMQvT7sXX7c9YdbTjyglyGqhXUN8h+mIRlP9IStD
    -----END PKCS7-----

Remember that the above formatting serves only for the purpose of testing the
encryption with OpenSSL. Do not make such enclosing in e-mails.


License
=======

This software is licensed under the Apache License 2.0. See the LICENSE file in
the top distribution directory for the full license text.


Versioning
==========

This software follows `Semantic Versioning`_


.. _asn1crypto: https://github.com/wbond/asn1crypto
.. _Semantic Versioning: http://semver.org/
