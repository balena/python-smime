from cStringIO import StringIO
from pyasn1_modules import rfc2459, pem
from pyasn1.codec.ber import decoder

def parse(pem_cert):
    """
    Parse the given certificate in PEM format and return the ASN.1 representation of it.
    """
    armours = [
        ('-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'),
        ('-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'),
        ('-----BEGIN RSA PUBLIC KEY-----', '-----END RSA PUBLIC KEY-----')
    ]
    substrate = None
    for armour in armours:
        idx, substrate = pem.readPemBlocksFromFile(StringIO(pem_cert), armour)
        if substrate:
            break
    if not substrate:
        raise ValueError('bad PKCS7 data on input')

    return decoder.decode(substrate, asn1Spec=rfc2459.Certificate())


def getkey(cert):
    pass # TODO


if __name__ == "__main__":
    import sys

    substrate = sys.stdin.read()
    while len(substrate) > 0:
        content, substrate = parse(substrate)
        print(content.prettyPrint())