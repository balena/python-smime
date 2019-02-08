#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import os
import sys
from email import message_from_string
from subprocess import PIPE
from subprocess import Popen
from tempfile import mkstemp

from smime.api import encrypt


def get_cmd_output(args):
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
        sys.stderr.write("Command: %s\n%s" % (" ".join(args), "".join(error)))
    return "\n".join(result)


def assert_message_to_carl(settings, algorithm):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            "Subject: A message from python",
            "",
            "Now you see me.",
        ]
        with open(settings['carl_public_certificate']) as cert:
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
            settings['carl_private_certificate'],
        ]
        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()

        assert "Now you see me." == payload[len(payload) - 1]

        return 1


def test_message_to_carl_aes256_cbc(base_settings):
    settings = base_settings
    assert assert_message_to_carl(settings, u"aes256_cbc") == 1


def test_message_to_carl_aes192_cbc(base_settings):
    settings = base_settings
    assert assert_message_to_carl(settings, u"aes192_cbc") == 1


def test_message_to_carl_aes128_cbc(base_settings):
    settings = base_settings
    assert assert_message_to_carl(settings, u"aes128_cbc") == 1
