#!/usr/bin/env python

"""cert_util.py: X509 certificate parsing utility.

Usage:

  cert_util.py [flags] [cert_file ...]

  Print information about the certificates in given files.

  Each file must contain either one or more PEM-encoded certificates,
  or a single DER certificate.

  For example:

  cert_util.py cert.pem           - pretty-print the certificate(s)
  cert_util.py c1.pem c2.pem      - pretty-print certificates from
                                    multiple files
  cert_util.py cert.der           - both PEM and DER are accepted formats
                                    (use --filetype to force a format)
  cert_util.py --debug cert.pem   - print full ASN.1 structure
  cert_util.py --subject cert.pem - print the subject name
  cert_util.py --issuer cert.pem  - print the issuer name
  cert_util.py --fingerprint cert.pem
                                  - print the SHA-1 fingerprint
  cert_util.py --fingerprint --digest="sha256" cert.pem
                                  - print the SHA-256 fingerprint
"""

import argparse
import sys

from smime import cert
from smime import print_util


def print_cert(args, certificate):
    if not args.subject and not args.issuer and not args.fingerprint:
        if args.debug:
            print(certificate.debug())
        else:
            print(certificate)
    else:
        if args.subject:
            print(("subject:\n%s" % certificate.print_subject_name()))
        if args.issuer:
            print(("issuer:\n%s" % certificate.print_issuer_name()))
        if args.fingerprint:
            # Print in a format familiar from OpenSSL.
            print(("%s fingerprint: %s\n" % (
                args.digest.upper(), print_util.bytes_to_hex(
                    certificate.fingerprint(hashfunc=args.digest)))))


def print_certs(args, cert_file):
    """Print the certificates, or parts thereof, as specified by flags."""
    # If no format is specified, try PEM first, and automatically fall back
    # to DER. The advantage is that usage is more convenient; the disadvantage
    # is that error messages are less helpful because we don't know the expected
    # file format.
    printed = False
    if not args.filetype or args.filetype.lower() == "pem":
        if not args.filetype:
            print("Attempting to read PEM")

        try:
            for c in cert.certs_from_pem_file(cert_file):
                print_cert(args, c)
                printed = True
        except Exception as e:
            if not printed:
                # Immediate error
                print(("File is not a valid PEM file: %s" % e))
            else:
                exit_with_message("Error while scanning PEM blocks: %s" % e)

    if not printed and args.filetype.lower() != "pem":
        if not args.filetype:
            print("Attempting to read raw DER")
        try:
            print_cert(args,
                       cert.Certificate.from_der_file(cert_file))
        except Exception as e:
            exit_with_message("Failed to parse DER from %s" % cert_file)


def exit_with_message(error_message):
    print(error_message)
    print("Use --help to get help.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Print information about the certificates in given files.')
    parser.add_argument('--subject', action='store_true',
                        help='prints certificate subject')
    parser.add_argument('--issuer', action='store_true',
                        help='prints certificate issuer')
    parser.add_argument('--fingerprint', action='store_true',
                        help='prints certificate fingerprint')
    parser.add_argument('--digest', default='sha1',
                        help='fingerprint digest to use')
    parser.add_argument('--debug', action='store_true',
                        help='prints full ASN.1 debug information')
    parser.add_argument('--filetype', default='', choices=['pem', 'der'],
                        help='specify an input file format (pem or der). '
                             'If no format is specified, the parser attempts '
                             'to detect the format automatically.')
    parser.add_argument('cert_files', nargs='+', metavar='cert_file',
                        help='PEM or DER encoded certificate file')
    args = parser.parse_args()

    for filename in args.cert_files:
        print_certs(args, filename)
    sys.exit(0)


if __name__ == "__main__":
    main()
