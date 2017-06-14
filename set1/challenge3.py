#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

import sys
from sys import argv
import binascii
import collections
import string


def xor(string, byte):
    binary = bytearray(binascii.unhexlify(string))
    for i in range(len(binary)):
        binary[i] ^= byte
    try:
        return binary.decode('utf-8','surrogatepass')
    except UnicodeDecodeError:
        return ""

def test(hex_string):
    for i in range(0,255):
       s = xor(hex_string, i)
       valid = True
       if s == "":
           valid = False
       validchars = set(string.printable)
       if not set(s).issubset(validchars):
           valid = False
       if valid:
           print(s, "\t|\tbyte:", i)
    return

if __name__ == '__main__':
    if len(argv[1:]) == 1:
        test(argv[1])
    else:
        print("Usage: ",argv[0]," [hex_string]\nOutput: list of reasonable results from xor'ing the hex encoded string with a single repeating byte")
