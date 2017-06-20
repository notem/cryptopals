#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

import sys
from sys import argv
import binascii
import collections
import string


def xor_encode(text, key):
    system_encoding=sys.getdefaultencoding()
    binary = bytearray(text, encoding=system_encoding)
    key_binary = bytearray(key, encoding=system_encoding)
    key_index = 0

    for i in range(len(binary)):
        binary[i] ^= key_binary[key_index]
        key_index += 1
        if key_index >= len(key_binary):
            key_index = 0

    return binascii.hexlify(binary).decode()

if __name__ == '__main__':
        text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key = "ICE"
        encoded_string = xor_encode(text, key)
        print(encoded_string)
