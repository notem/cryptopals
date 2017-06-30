#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-06-19

import sys
from sys import argv
import base64
import collections
import string
import challenge3
import challenge5


# find the haming distance between two equal length pieces of binary data
def hamming_distance(binary1, binary2):
    distance = -1
    if len(binary1) == len(binary2):
        distance = 0
        for i in range(len(binary1)):
            distance += byte_difference(binary1[i], binary2[i])
    return distance

# count the number of different bits for between two bytes
def byte_difference(byte1, byte2):
    difference = 0
    for i in range(8):
        mask = 1<<i
        if (byte1 & mask) != (byte2 & mask):
            difference += 1
    return difference

# use the hamming distance to guess the 3 most likely
# keysizes used to encode the data
def probable_keysizes(binary, max_keysize):
    first_size = -1
    first_diff = 99*99*99
    second_size = -1
    second_diff = 99*99*99
    third_size = -1
    third_diff = 99*99*99

    for key_size in range(2, max_keysize+1):
        blocks = [binary[x:(key_size+x)] for x in range(0, len(binary), key_size)][:4]
        dif1 = hamming_distance(blocks[0], blocks[1]) + hamming_distance(blocks[1], blocks[2]) + hamming_distance(blocks[2], blocks[3])
        dif2 = hamming_distance(blocks[0], blocks[2]) + hamming_distance(blocks[0], blocks[3]) + hamming_distance(blocks[1], blocks[3])
        dif = dif1 + dif2 / 6
        dif /= key_size

        # if distance is greater than the old highest
        # move first to second, second to third, and the current size to first
        if dif < first_diff:
            third_size = second_size
            third_diff = second_diff
            second_size = first_size
            second_diff = first_diff
            first_size = key_size	
            first_diff = dif
        # if distance is greater than the old second highest
        # move second to third and the current size to second
        elif dif < second_diff:
            third_size = second_size
            third_diff = second_diff
            second_size = key_size
            second_diff = dif
        # if distance is greater than the old third highest
        # place the current size in third
        elif dif < third_diff:
            third_size = key_size
            third_diff = dif

    return (first_size, second_size, third_size)

# identify the three most likely xor keys
# and decode the plaintext
def decipher(binary_data):
    keysizes = probable_keysizes(binary, 40)
    results = {}

    # for all probable keysizes
    for keysize in keysizes:
        key = bytearray()

        # break the binary data into blocks
        # one block for each byte of the key
        for i in range(keysize):
            block = bytearray()

            # form the block
            for j in range(i, len(binary_data), keysize):
                block.append(binary_data[j])

            # guess the xor key for that block
            best_byte = challenge3.decipher(block)[0]
            if best_byte >= 0:
                key.append(best_byte)
            else:
                break

        if len(key) > 0:
            results[bytes(key)] = challenge5.xor_encode(binary_data, key)

    return results

if __name__ == '__main__':
    file_obj = open("chall6.txt", "r")
    
    # confirm the hamming distance function is correct
    function_test = hamming_distance(bytearray("this is a test", 'utf-8'), bytearray("wokka wokka!!!", 'utf-8'))
    assert function_test == 37

    # combine lines and decode the file from base64
    encodedtext = ""
    for line in file_obj
        encodedtext += line.strip()
    binary = bytearray(base64.b64decode(encodedtext))
    
    # attempt to decrypt the binary data
    results = decipher(binary)
    for key in results.keys():
        print("key:", key.decode('utf-8'))
        print("\n-P-L-A-I-N- -T-E-X-T- -R-E-S-U-L-T-S-")
        print(results[key].decode('utf-8'))
        print("-------------------------------------")

