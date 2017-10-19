/*
Solution to cryptopals challenge 12
http://cryptopals.com/sets/2/challenges/12

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-19
*/
package main

import (
	"crypto/aes"
	"../utils"
	"encoding/base64"
	"fmt"
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
func ECBOracle(data []byte) ([]byte) {

	// append the secret data to the user supplied data
	secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	decoded, _ := base64.RawStdEncoding.DecodeString(secret)
	for _, decodedByte := range decoded {
		data = append(data, decodedByte)
	}

	blockSize := aes.BlockSize			// set block size
	data = utils.Pad(blockSize, data)	// pad the data
	crypt := make([]byte, len(data))	// encrypted byte array storage

	key := make([]byte, blockSize)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// ECB mode, encrypt each block in data
	for i:=0; i<len(data); i+=blockSize {
		cipher.Encrypt(crypt[i:i+blockSize], data[i:i+blockSize])
	}
	return crypt
}

// discover the secret that the ECBOracle is hiding
// block size should have been determined previously
func CrackSecret(blockSize uint) ([]byte) {

	sizeOfSecret := len(ECBOracle(make([]byte,0)))
	fmt.Printf("%q\n", utils.ECBDecrypt(ECBOracle(make([]byte,0)), make([]byte, blockSize)))
	secret := make([]byte,0)
	known := make([]byte, blockSize-1)		// known 0 byte array
	for len(secret) < sizeOfSecret {		// while the secret is not filled
		offset := uint(len(secret))			// offset to the current block

		// crack each byte of the current block
		for i:=uint(0); i<blockSize; i++ {
			crypt := ECBOracle(make([]byte, blockSize-1-i)) // generate the cipher text with the short block
			block := string(crypt[offset:blockSize+offset]) // slice out the current block
			discovered := byte(0)

			// find which final byte generates a matching cipher text
			for j:=0; j<=255; j++ {
				// generate the cipher for byte j
				crypt = ECBOracle(append(known, byte(j)))

				// compare and break if match is found
				if string(crypt[0:blockSize]) == block {
					discovered = byte(j)
					break
				} else if j==255 {
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
