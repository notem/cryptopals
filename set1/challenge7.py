#!/usr/bin/env python3
# coding: utf-8
# author: Nate Mathews, njm3308@rit.edu
# date: 2017-09-30

from Crypto import Random
from Crypto.Cipher import AES
import base64


def decrypt(encrypted, passphrase):
    aes = AES.new(passphrase, AES.MODE_ECB, Random.new().read(32))
    return aes.decrypt(base64.b64decode(encrypted))


if __name__ == '__main__':
    file_obj = open("chall7.txt", "r")

    encrypted = ""
    for line in file_obj:
        encrypted += line.strip()

    print(decrypt(encrypted, "YELLOW SUBMARINE").decode())


