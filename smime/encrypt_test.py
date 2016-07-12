#!/usr/bin/env python
# coding=utf-8

from __future__ import unicode_literals

import os
import unittest
from subprocess import Popen, PIPE
from tempfile import mkstemp

from smime.test import test_config
from smime import encrypt

from email import message_from_string


class EncryptTest(unittest.TestCase):
    _CARL_PUBLIC_CERTIFICATE = 'CarlRSASelf.pem'
    _CARL_PRIVATE_CERTIFICATE = 'CarlPrivRSASign.pem'

    def get_file(self, filename):
        return test_config.get_test_file_path(filename)

    def get_cmd_output(self, args):
        child = Popen(args, stdout=PIPE, stderr=PIPE)
        result = []
        while True:
            for line in iter(child.stdout.readline, ''):
                result.append(line)
            if child.poll() is not None:
                break
        if child.returncode != 0:
            error = []
            for line in iter(child.stderr.readline, ''):
                error.append(line)
            self.fail(("Command: %s\n%s" %
                      (' '.join(args), ''.join(error))))
        return '\n'.join(result)

    def assertMessageToCarlWith(self, algorithm):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            'Subject: A message from python',
            '',
            'Now you see me.'
        ]
        with open(self.get_file(self._CARL_PUBLIC_CERTIFICATE)) as cert:
            result = encrypt('\n'.join(message), cert.read(), algorithm=algorithm)
        fd, tmp_file = mkstemp()
        os.write(fd, result)

        cmd = [
            'openssl', 'smime', '-decrypt',
            '-in', tmp_file,
            '-inkey', self.get_file(self._CARL_PRIVATE_CERTIFICATE)
        ]
        cmd_output = self.get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()
        self.assertEquals('Now you see me.', payload[len(payload)-1])

    def test_message_to_carl_aes256_cbc(self):
        self.assertMessageToCarlWith('aes256_cbc')

    def test_message_to_carl_aes192_cbc(self):
        self.assertMessageToCarlWith('aes192_cbc')

    def test_message_to_carl_aes128_cbc(self):
        self.assertMessageToCarlWith('aes128_cbc')


if __name__ == "__main__":
    unittest.main()
