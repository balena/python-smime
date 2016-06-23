import sys
from cStringIO import StringIO
from pyasn1.codec.der import encoder, decoder

from pyasn1_modules import pem

from rfc5652 import id_envelopedData, SignedData, id_digestedData, id_encryptedData, id_authenticatedData, Data, \
    id_data, DigestedData, ContentInfo, AuthenticatedData, id_signedData, EncryptedData, EnvelopedData

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

contentInfo, rest = decoder.decode(substrate, asn1Spec=ContentInfo())

if rest: substrate = substrate[:-len(rest)]

#print(contentInfo.prettyPrint())

assert encoder.encode(contentInfo, defMode=False) == substrate or \
       encoder.encode(contentInfo, defMode=True) == substrate, \
    're-encode fails'

contentType = contentInfo.getComponentByName('contentType')

contentInfoMap = {
    id_data.asTuple(): Data(),
    id_signedData.asTuple(): SignedData(),
    id_envelopedData.asTuple(): EnvelopedData(),
    id_digestedData.asTuple(): DigestedData(),
    id_encryptedData.asTuple(): EncryptedData(),
    id_authenticatedData.asTuple(): AuthenticatedData(),
}

content, _ = decoder.decode(
    contentInfo.getComponentByName('content'),
    asn1Spec=contentInfoMap[contentType]
)

print(content.prettyPrint())
