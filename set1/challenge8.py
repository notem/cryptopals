#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-09-30


def rank(cipher):
    rank = 0
    blocks = [cipher[i:i+16] for i in range(0, len(cipher), 16)]
    distinct_blocks = set()
    for block in blocks:
        if block in distinct_blocks:
            rank += 1
        else:
            distinct_blocks.add(block)
    return rank


if __name__ == '__main__':
    file_obj = open("chall8.txt", "r")

    toprank = 0
    topline = ""
    topno = ""

    encrypted = ""
    counter = 0
    for line in file_obj:
        val = rank(line.strip())
        counter += 1
        if val >= toprank:
            topline = line
            topno = counter
            toprank = val

    print("Found ", toprank, " repeating blocks on line #", topno, "\n", topline)
