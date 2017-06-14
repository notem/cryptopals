#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

import sys
from sys import argv
import binascii


def xor(string, byte):
    binary = bytearray(binascii.unhexlify(string))
    for i in range(len(binary)):
        binary[i] ^= byte
    try:
        return binary.decode()
    except UnicodeDecodeError:
        return "Error"

if __name__ == '__main__':
    if len(argv[1:]) == 1:
        for i in range(0,255):
            hex_str = xor(argv[1], i)
            print(hex_str, "\t|\tbyte:", i)
    else:
        print("Usage: ",argv[0]," [hex_string]\nOutput: list of all results of xor'ing the hex encoded string with a single repeating byte")
