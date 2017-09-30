#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

from sys import argv
import binascii


def xor(string1, string2):
    # convert to byte arrays
    binary1 = bytearray(binascii.unhexlify(string1))
    binary2 = bytearray(binascii.unhexlify(string2))

    # xor each byte
    for i in range(len(binary1)):
        binary1[i] ^= binary2[i]

    # convert back to a hex string
    return binascii.hexlify(binary1)


if __name__ == '__main__':
    if len(argv[1:]) == 2:
        len1 = len(argv[1])
        len2 = len(argv[2])
        if len1 == len2:
            hex_str = xor(argv[1], argv[2])
            print(hex_str.decode())
        else:
            print("Error: hex strings must be of same length!")
    else:
        print(
        "Usage: ", argv[0], " [hex_string1] [hex_string2]\nOutput: result of xor of provided strings, base16 encoded")
