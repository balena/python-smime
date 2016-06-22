from cStringIO import StringIO
import rfc3369
from pyasn1_modules import pem
from pyasn1.codec.der import encoder, decoder
import sys

#from pyasn1 import debug
#debug.setLogger(debug.Debug('all'))

if len(sys.argv) != 1:
    print("""Usage:
$ cat smime.p7m | %s""" % sys.argv[0])
    sys.exit(-1)

cert = sys.stdin.read()
armours = [
    ('-----BEGIN PKCS7-----', '-----END PKCS7-----'),
    ('', ''),
]
for armour in armours:
    idx, substrate = pem.readPemBlocksFromFile(StringIO(cert), armour)
    if substrate:
        break
else:
    substrate = None

assert substrate, 'bad S/MIME data on input'

contentInfo, rest = decoder.decode(substrate, asn1Spec=rfc3369.ContentInfo())

if rest: substrate = substrate[:-len(rest)]

#print(contentInfo.prettyPrint())

assert encoder.encode(contentInfo, defMode=False) == substrate or \
       encoder.encode(contentInfo, defMode=True) == substrate, \
    're-encode fails'

contentType = contentInfo.getComponentByName('contentType')

contentInfoMap = {
    rfc3369.id_data.asTuple(): rfc3369.Data(),
    rfc3369.id_signedData.asTuple(): rfc3369.SignedData(),
    rfc3369.id_envelopedData.asTuple(): rfc3369.EnvelopedData(),
    rfc3369.id_digestedData.asTuple(): rfc3369.DigestedData(),
    rfc3369.id_encryptedData.asTuple(): rfc3369.EncryptedData(),
    rfc3369.id_authenticatedData.asTuple(): rfc3369.AuthenticatedData(),
}

content, _ = decoder.decode(
    contentInfo.getComponentByName('content'),
    asn1Spec=contentInfoMap[contentType]
)

print(content.prettyPrint())
