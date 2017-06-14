#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

from sys import argv
import binascii


def base16ToBase64(string):
    binary = binascii.unhexlify(string)
    return binascii.b2a_base64(binary)

if __name__ == '__main__':
    if len(argv[1:]) == 1:
        base64 = base16ToBase64(argv[1])
        print(base64)
    else:
        print("Usage: prog [hex_string]\nOutput: Base64 encoded string")
