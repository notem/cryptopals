/*
Solution to cryptopals challenge 14
http://cryptopals.com/sets/2/challenges/14
------------------
Take your oracle function from #12. Now generate a random count of random bytes and prepend this
string to every plaintext.

Same goal: decrypt the target-bytes.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

To decrypt the appended secret string, the CrackSecret() function must first find the number of
user input bytes to include in order for the appending secret to start on it's own block of the
cipher-text. The exact location in which the secret begins must also be identified.

Once these two pieces of information are obtained, the secret can be cracked using the general
method as seen in the solution for challenge #12
*/
package main

import (
	"../utils"
	"fmt"
	"math/rand"
)

var (
	target = []byte("This is some secret text which is greater than one block long!") // the secret
	aesKey = utils.RandomByteArray(16)
	prefix = utils.RandomByteArray(rand.Int() % 30)
)

// main loadpoint
func main() {
	blockSize := utils.DetectBlockSize(ECBOracle)
	secret := CrackSecret(int(blockSize))

	fmt.Printf("The secret is: %q\n", secret)
	if string(secret) != string(target) {
		fmt.Println("Failed to crack the secret!")
	}
}

// encryption black box which encrypts known plaintext concatenated with an unknown secret
// under AES operating in ECB mode
func ECBOracle(data []byte) []byte {

	data = append(append(prefix, data...), target...)
	crypt, err := utils.ECBEncrypt(data, aesKey)
	if err != nil {
		panic(err)
	}
	return crypt
}

// discover the secret that the ECBOracle is hiding
// block size should have been determined previously
func CrackSecret(blockSize int) []byte {

	// this loop identifies the index finds the number of bytes required to fill the prefix to a block boundary
	// and establishes the index for the boundary between the prefix blocks and the secret blocks
	boundary := -1
	var count int
	for count = 1; count < blockSize; count++ {

		data := make([]byte, count+blockSize*2)
		crypt := ECBOracle(data)
		for i := blockSize; i < len(crypt); i += blockSize {

			if string(crypt[i-blockSize:i]) == string(crypt[i:i+blockSize]) {
				boundary = i - blockSize
				break
			}
		}
		// break loop if the boundary between the prefix block and secret block was found
		if boundary > 0 {
			break
		}
	}

	// using the count of byte required to fill the prefix to a block and the index which
	// deliminates the prefix blocks from the secret blocks, the secret can now be bruteforced
	sizeOfSecret := len(ECBOracle(make([]byte, count))[boundary:])
	secret := make([]byte, 0)
	known := make([]byte, (blockSize+count)-1) // known 0 byte array
	for len(secret) < sizeOfSecret {           // while the secret is not filled

		offset := len(secret) + boundary // offset to the current block

		// crack each byte of the current block
		for i := 0; i < blockSize; i++ {

			crypt := ECBOracle(make([]byte, (blockSize+count)-1-i)) // generate the cipher text with the short block
			block := string(crypt[offset : blockSize+offset])       // slice out the current block
			discovered := byte(0)

			// find which final byte generates a matching cipher text
			for j := 0; j <= 255; j++ {
				// generate the cipher for byte j
				crypt = ECBOracle(append(known, byte(j)))

				// compare and break if match is found
				if string(crypt[boundary:blockSize+boundary]) == block {
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
