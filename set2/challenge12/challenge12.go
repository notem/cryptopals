/*
Solution to cryptopals challenge 12
http://cryptopals.com/sets/2/challenges/12
------------------
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown
key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string: ...

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it.
The point is that you don't know its contents.

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then
	"AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

2. Detect that the function is using ECB. You already know, but do this step anyways.

3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is
	8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.

4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance,
	"AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered
	the first byte of unknown-string.

6. Repeat for the next byte.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

The ECB Oracle function appends user supplied data with the secret and encrypts with AES-ECB under an unknown key
The encryption function can be found in 'crypto.go' of the utils package

This program is not interactive
*/
package main

import (
	"../utils"
	"encoding/base64"
	"fmt"
)

var (
	secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaG" +
		"FpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ" +
		"pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	aesKey = utils.RandomByteArray(16)
)

// main loadpoint
func main() {

	// determine block size
	blockSize := utils.DetectBlockSize(ECBOracle)
	fmt.Println("=> Blocksize is", blockSize, "bytes")

	// ECB test
	if utils.DetectECB(int(blockSize), ECBOracle(make([]byte, blockSize*3))) {
		fmt.Println("==> Detected ECB")
		// crack the ECB Oracle's secret!
		secret := CrackSecret(blockSize)
		fmt.Println(string(secret))
	}
}

// encryption black box which encrypts known plaintext concatenated with an unknown secret
// under AES operating in ECB mode
func ECBOracle(data []byte) []byte {

	// append the secret data to the user supplied data
	decoded, _ := base64.RawStdEncoding.DecodeString(secret)
	for _, decodedByte := range decoded {
		data = append(data, decodedByte)
	}

	// encrypt the input appended with the secret under an unknown key
	crypt, err := utils.ECBEncrypt(data, aesKey)
	if err != nil {
		panic(err)
	}
	return crypt
}

// discover the secret that the ECBOracle is hiding
// block size should have been determined previously
func CrackSecret(blockSize uint) []byte {

	sizeOfSecret := len(ECBOracle(make([]byte, 0)))
	secret := make([]byte, 0)
	known := make([]byte, blockSize-1) // known 0 byte array
	for len(secret) < sizeOfSecret {   // while the secret is not filled
		offset := uint(len(secret)) // offset to the current block

		// crack each byte of the current block
		for i := uint(0); i < blockSize; i++ {
			crypt := ECBOracle(make([]byte, blockSize-1-i))   // generate the cipher text with the short block
			block := string(crypt[offset : blockSize+offset]) // slice out the current block
			discovered := byte(0)

			// find which final byte generates a matching cipher text
			for j := 0; j <= 255; j++ {
				// generate the cipher for byte j
				crypt = ECBOracle(append(known, byte(j)))

				// compare and break if match is found
				if string(crypt[0:blockSize]) == block {
					discovered = byte(j)
					break
				} else if j == 255 {
					// cracking fails when the final block is reached due the block's padding
					// after processing one byte of pad. As a solution I've decided to simply shave
					// off the last byte and return whenever a block match is not found.
					return secret[:len(secret)-1]
				}
			}

			secret = append(secret, discovered)   // append discovered byte to secret
			known = append(known, discovered)[1:] // append discovered byte to known block, and splice to blocksize-1
		}
	}
	return secret
}
