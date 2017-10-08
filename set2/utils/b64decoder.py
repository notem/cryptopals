#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-10-08
# description: useful utility for decoding a base 64 encoded file into a binary file

from sys import argv
import base64


if __name__ == '__main__':
    if len(argv[1:]) != 2:
        print("Decodes a file encoded in Base 64 and write out to a file.\n",
              "Usage: ", argv[0],"[infile] [outfile]")
        exit(1)

    infile = open(argv[1], "r")
    outfile = open(argv[2], "wb")

    encrypted = ""
    for line in infile:
        encrypted += line.strip()
    infile.close()

    outfile.write(base64.b64decode(encrypted))
    outfile.close()
