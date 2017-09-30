#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-28

from sys import argv
import binascii

challenge3 = __import__("challenge3")


if __name__ == '__main__':
    if len(argv[1:]) == 1:
        file_obj = open(argv[1], "r")
        line_no = 1

        valid_results = {}
        for string in file_obj:
            binary = bytearray(binascii.unhexlify(string.strip()))
            top = challenge3.decipher(binary)
            if top[0] >= 0:
                results = challenge3.xor(binary, top[0]).decode('utf-8')
                valid_results[line_no] = [top[0], results]
            line_no += 1

        best_score = -1
        best_line = -1

        for key in valid_results.keys():
            score = challenge3.grade(valid_results[key][1])
            if score > best_score:
                best_score = score
                best_line = key

        print("Line", best_line)
        print("Byte:   ", valid_results[best_line][0])
        print("Results:", valid_results[best_line][1])
    else:
        print("Usage: ", argv[0],
              "[hex_string]\nOutput: for lines in the file, outputs the best decryptions of the string using a one ",
              "byte xor key")
