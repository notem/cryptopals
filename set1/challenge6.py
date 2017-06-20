#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

import sys
from sys import argv
import binascii
import collections
import string

def hamming_difference(str1, str2):
    difference = -1

    if len(str1) == len(str2):
        difference = 0

        system_encoding=sys.getdefaultencoding()
        binary1 = bytearray(str1, encoding=system_encoding)
        binary2 = bytearray(str2, encoding=system_encoding)

        for i in range(len(binary1)):
            difference += byte_difference(binary1[i], binary2[i])

    return difference

def byte_difference(byte1, byte2):
    difference = 0
    for i in range(8):
        mask = 1<<i
        if (byte1 & mask) != (byte2 & mask):
            difference += 1
    return difference

if __name__ == '__main__':
        str1 = "this is a test"
        str2 = "wokka wokka!!!"
        print(hamming_difference(str1, str2))
