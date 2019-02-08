#!/usr/bin/env python
from smime import print_util


def test_bits_to_hex():
    bit_array = [0, 1, 1, 0, 1, 0, 1, 1, 1, 0]
    assert "01:ae" == print_util.bits_to_hex(bit_array)
    assert "01ae" == print_util.bits_to_hex(bit_array, delimiter="")
    assert "" == print_util.bits_to_hex("")


def test_bytes_to_hex():
    byte_array = "\x01\xae"
    assert "01:ae" == print_util.bytes_to_hex(byte_array)
    assert "01ae" == print_util.bytes_to_hex(byte_array, delimiter="")
    assert "" == print_util.bytes_to_hex("")


def test_int_to_hex():
    integer = 1234  # 0x4d2
    assert "04:d2" == print_util.int_to_hex(integer)
    assert "04d2" == print_util.int_to_hex(integer, delimiter="")

    negative_integer = -1234
    assert " -:04:d2" == print_util.int_to_hex(negative_integer)


def test_wrap_lines():
    long_multiline_string = "hello\nworld"
    assert ["hel", "lo", "wor", "ld"] == print_util.wrap_lines(long_multiline_string, 3)


def test_wrap_lines_no_wrap():
    long_multiline_string = "hello\nworld"
    assert ["hello", "world"] == print_util.wrap_lines(long_multiline_string, 0)


def test_append_lines_appends():
    buf = ["hello"]
    lines = ["beautiful", "world"]
    # "hellobeautiful" is more than 10 characters long
    print_util.append_lines(lines, 20, buf)
    assert ["hellobeautiful", "world"] == buf


def test_append_lines_honours_wrap():
    buf = ["hello"]
    lines = ["beautiful", "world"]
    # "hellobeautiful" is more than 10 characters long
    print_util.append_lines(lines, 10, buf)
    assert ["hello", "beautiful", "world"] == buf
