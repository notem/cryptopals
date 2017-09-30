#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

import sys
import binascii
import copy


# encode binary data by xor'ing a key repeating through the length of the data
def xor_encode(binary, key_binary):
    binary_clone = copy.deepcopy(binary)

    key_index = 0
    for i in range(len(binary)):
        binary_clone[i] ^= key_binary[key_index]
        key_index += 1
        if key_index >= len(key_binary):
            key_index = 0

    return binary_clone


if __name__ == '__main__':
    text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"

    system_encoding = sys.getdefaultencoding()
    binary = bytearray(text, encoding=system_encoding)
    key_binary = bytearray(key, encoding=system_encoding)

    encoded_string = binascii.hexlify(xor_encode(binary, key_binary)).decode()
    print(encoded_string)
