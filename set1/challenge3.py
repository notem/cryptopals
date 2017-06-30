#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-28

import sys
from sys import argv
import binascii
import collections
import string
import copy

# simply does the xor operation on every byte of a string
# using a constant byte value
def xor(binary, byte):
    binary_clone = copy.deepcopy(binary)
    for i in range(len(binary)):
        binary_clone[i] ^= byte
    return binary_clone

# old function for 'scoring' the validity of a string
# compares the standard letter frequencies for english language
# the lowest point value is the 'best'
def grade_old(string):
    standard_frequency = {
        'a': 0.0651738,
        'b': 0.0124248,
        'c': 0.0217339,
        'd': 0.0349835,
        'e': 0.1041442,
        'f': 0.0197881,
        'g': 0.0158610,
        'h': 0.0492888,
        'i': 0.0558094,
        'j': 0.0009033,
        'k': 0.0050529,
        'l': 0.0331490,
        'm': 0.0202124,
        'n': 0.0564513,
        'o': 0.0596302,
        'p': 0.0137645,
        'q': 0.0008606,
        'r': 0.0497563,
        's': 0.0515760,
        't': 0.0729357,
        'u': 0.0225134,
        'v': 0.0082903,
        'w': 0.0171272,
        'x': 0.0013692,
        'y': 0.0145984,
        'z': 0.0007836,
        ' ': 0.1918182 
    }

    frequency_count = {
        'a': 0,
        'b': 0,
        'c': 0,
        'd': 0,
        'e': 0,
        'f': 0,
        'g': 0,
        'h': 0,
        'i': 0,
        'j': 0,
        'k': 0,
        'l': 0,
        'm': 0,
        'n': 0,
        'o': 0,
        'p': 0,
        'q': 0,
        'r': 0,
        's': 0,
        't': 0,
        'u': 0,
        'v': 0,
        'w': 0,
        'x': 0,
        'y': 0,
        'z': 0,
        ' ': 0 
    }


    for char in string.lower():
        if char in frequency_count:
            frequency_count[char] += 1
    
    for key in frequency_count.keys():
        frequency_count[key] == frequency_count[key]/len(string)
    
    points = 0
    for key in standard_frequency.keys():
        points += abs(standard_frequency[key] - frequency_count[key])

    return points

# new function for scoring strings
# simpler than the old function, for every character in the string
# this function simply adds the standard frequency for that letter to
# the points letter. The most 'valid' string would thus be all whitespace
# higher point values are better
def grade(string):
    standard_frequency = {
        'a': 0.0651738,
        'b': 0.0124248,
        'c': 0.0217339,
        'd': 0.0349835,
        'e': 0.1041442,
        'f': 0.0197881,
        'g': 0.0158610,
        'h': 0.0492888,
        'i': 0.0558094,
        'j': 0.0009033,
        'k': 0.0050529,
        'l': 0.0331490,
        'm': 0.0202124,
        'n': 0.0564513,
        'o': 0.0596302,
        'p': 0.0137645,
        'q': 0.0008606,
        'r': 0.0497563,
        's': 0.0515760,
        't': 0.0729357,
        'u': 0.0225134,
        'v': 0.0082903,
        'w': 0.0171272,
        'x': 0.0013692,
        'y': 0.0145984,
        'z': 0.0007836,
        ' ': 0.1918182 
    }

    points = 0
    for char in string.lower():
        if char in standard_frequency:
            points += standard_frequency[char]

    return points

# identifies the three most likely bytes which may have been used
# to encode the hex string
def decipher(binary):
    top_1_byte = -1
    top_1_points = -1
    top_2_byte = -1
    top_2_points = -1
    top_3_byte = -1
    top_3_points = -1

    # for every possible byte
    for i in range(0,256):
       try:
           s = xor(binary, i).decode('utf-8', 'surrogatepass')
       except UnicodeDecodeError:
           s = ""

       valid = True
       if s == "":
           valid = False

       # exclude strings containing non printable characters
       #validchars = set(string.printable)
       #if not set(s).issubset(validchars):
       #    valid = False

       if valid:
           points = grade(s)

           if points > top_1_points:
               top_3_points = top_2_points
               top_3_byte = top_2_byte
               top_2_points = top_1_points
               top_2_byte = top_1_byte
               top_1_points = points
               top_1_byte = i
           elif points > top_2_points:
               top_3_points = top_2_points
               top_3_byte = top_2_byte
               top_2_points = points
               top_2_byte = i
           elif points > top_3_points:
               top_3_points = points
               top_3_byte = i

    return (top_1_byte, top_2_byte, top_3_byte)

if __name__ == '__main__':
    if len(argv[1:]) == 1:
        binary_data = bytearray(binascii.unhexlify(argv[1]))
        top_bytes = decipher(binary_data)
        print("Byte:  ", top_bytes[0])
        print("Result:", xor(binary_data, top_bytes[0]).decode('utf-8'))
    else:
        print("Usage: ",argv[0]," [hex_string]\nOutput: list of reasonable results from xor'ing the hex encoded string with a single repeating byte")
