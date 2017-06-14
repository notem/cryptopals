#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-14

import sys
from sys import argv
import binascii
import collections
import string
import challenge3


if __name__ == '__main__':
    if len(argv[1:]) == 1:
        file_obj = open(argv[1],"r")
        line_no = 1;
        for string in file_obj:
            print("Testing line number ", line_no,". . .")
            challenge3.test(string.strip())
            line_no += 1
    else:
        print("Usage: ",argv[0]," [hex_string]\nOutput: for every line in the file, outputs all reasonable decryptions of the string using a one byte xor key")
