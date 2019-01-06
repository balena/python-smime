#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import os
import unittest
from email import message_from_string
from subprocess import PIPE
from subprocess import Popen
from tempfile import mkstemp

from smime.api import encrypt
from smime.test import test_config


class EncryptTest(unittest.TestCase):
    _CARL_PUBLIC_CERTIFICATE = "CarlRSASelf.pem"
    _CARL_PRIVATE_CERTIFICATE = "CarlPrivRSASign.pem"

    def get_file(self, filename):
        return test_config.get_test_file_path(filename)

    def get_cmd_output(self, args):
        child = Popen(args, stdout=PIPE, stderr=PIPE)
        result = []
        while True:
            for line in iter(child.stdout.readline, ""):
                result.append(line)
            if child.poll() is not None:
                break
        if child.returncode != 0:
            error = []
            for line in iter(child.stderr.readline, ""):
                error.append(line)
            self.fail(("Command: %s\n%s" % (" ".join(args), "".join(error))))
        return "\n".join(result)

    def assertMessageToCarlWith(self, algorithm):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            "Subject: A message from python",
            "",
            "Now you see me.",
        ]
        with open(self.get_file(self._CARL_PUBLIC_CERTIFICATE)) as cert:
            result = encrypt(u"\n".join(message), cert.read(), algorithm=algorithm)
        fd, tmp_file = mkstemp()
        os.write(fd, result)

        cmd = [
            "openssl",
            "smime",
            "-decrypt",
            "-in",
            tmp_file,
            "-inkey",
            self.get_file(self._CARL_PRIVATE_CERTIFICATE),
        ]
        cmd_output = self.get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()
        self.assertEquals("Now you see me.", payload[len(payload) - 1])

    def test_message_to_carl_aes256_cbc(self):
        self.assertMessageToCarlWith(u"aes256_cbc")

    def test_message_to_carl_aes192_cbc(self):
        self.assertMessageToCarlWith(u"aes192_cbc")

    def test_message_to_carl_aes128_cbc(self):
        self.assertMessageToCarlWith(u"aes128_cbc")


if __name__ == "__main__":
    unittest.main()
