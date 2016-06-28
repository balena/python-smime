#!/usr/bin/env python

import unittest

from smime.crypto.asn1 import type_test_base
from smime.crypto.asn1 import cms_common


class LabeledIntegerTest(type_test_base.TypeTestBase):
    class TestLabeledInteger(cms_common.LabeledInteger):
        labels = (('foo', 1), ('bar', 2))

    asn1_type = TestLabeledInteger
    repeated = False
    keyed = False
    initializers = (
        # performed below
        )
    bad_initializers = (
        ('baz', ValueError),
        )
    encode_test_vectors = (
        (0, "020100"),
        ('foo', "020101"),
        ('bar', "020102")
        )
    bad_encodings = (
        # Same as Integer
        )
    bad_strict_encodings = (
        # Same as Integer
        )

    def test_initializers(self):
        foo = self.TestLabeledInteger('foo')
        o1 = self.asn1_type(value=foo)
        self.assertEqual(o1.value, 1)
        bar = self.TestLabeledInteger('bar')
        o2 = self.asn1_type(value=bar)
        self.assertEqual(o2.value, 2)
        bar = self.TestLabeledInteger(3)
        o2 = self.asn1_type(value=bar)
        self.assertEqual(o2.value, 3)

    def test_print(self):
        foo = self.TestLabeledInteger(1)
        self.assertEqual(str(foo), 'foo')


class EnumeratedTest(type_test_base.TypeTestBase):
    class Enumerated(cms_common.Enumerated):
        labels = (('foo', 1), ('bar', 2))

    asn1_type = Enumerated
    repeated = False
    keyed = False
    initializers = (
        # performed below
        )
    bad_initializers = (
        ('baz', TypeError),
        )
    encode_test_vectors = (
        ('foo', "0a0101"),
        ('bar', "0a0102")
        )
    bad_encodings = (
        # Same as Integer
        )
    bad_strict_encodings = (
        # Same as Integer
        )

    def test_initializers(self):
        foo = self.Enumerated('foo')
        self.assertEqual(foo.value, 1)
        bar = self.Enumerated('bar')
        self.assertEqual(bar.value, 2)

    def test_print(self):
        foo = self.Enumerated('foo')
        self.assertEqual(str(foo), 'foo')


if __name__ == '__main__':
    unittest.main()