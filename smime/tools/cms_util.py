#!/usr/bin/env python

"""cms_util.py: CMS parsing utility.

Usage:

  cms_util.py [flags] bin_file

  Print information about the encoded messages in file.

  The file must contain a DER or BASE64 content.

  For example:

  cms_util.py message.p7m          - pretty-print the message
  cms_util.py message.der          - both BASE64 and DER are accepted formats
                                     (use --filetype to force a format)
  cms_util.py --debug message.pem  - print full ASN.1 structure
"""

import argparse
import sys
from base64 import b64decode
from traceback import print_exc

from smime.crypto import error
from smime.crypto.asn1 import cms


def print_cms(args, message):
    if args.debug:
        print(("%r" % message))
    else:
        print((message.human_readable()))


def try_open(args, file):
    """Print the CMS content as specified by flags."""
    # If no format is specified, try PEM first, and automatically fall back
    # to DER. The advantage is that usage is more convenient; the disadvantage
    # is that error messages are less helpful because we don't know the expected
    # file format.
    strict_der = not args.lazy
    printed = False
    if not args.filetype or args.filetype == "base64":
        if not args.filetype:
            print("Attempting to read BASE64")

        try:
            der = b64decode(open(file, 'rb').read())
            print_cms(args, cms.from_string(der, strict_der=strict_der))
        except TypeError as e:
            if not printed:
                # Immediate error
                print(("File is not a valid BASE64 file: %s" % e))
            else:
                exit_with_message('Error while scanning BASE64 blocks')
        except error.ASN1Error as e:
            exit_with_message('Bad DER encoding')

    if not printed and args.filetype.lower() != "base64":
        if not args.filetype:
            print('Attempting to read raw DER')
        try:
            print_cms(args, cms.from_file(file, strict_der=strict_der))
        except error.ASN1Error as e:
            exit_with_message(('Failed to parse DER from %s' % file))


def exit_with_message(error_message):
    print_exc()
    print(error_message)
    print("Use --help to get help.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Print information about the CMS content.')
    parser.add_argument('--debug', action='store_true',
                        help='prints full ASN.1 debug information')
    parser.add_argument('--lazy', action='store_true',
                        help='tolerate non-fatal DER errors')
    parser.add_argument('--filetype', default='', choices=['base64', 'der'],
                        help='specify an input file format (base64 or der). '
                             'If no format is specified, the parser attempts '
                             'to detect the format automatically.')
    parser.add_argument('file', nargs=1, metavar='file',
                        help='PEM or DER encoded CMS file')
    args = parser.parse_args()

    try_open(args, args.file[0])
    sys.exit(0)


if __name__ == "__main__":
    main()
