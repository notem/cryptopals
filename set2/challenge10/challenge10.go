/*
Solution to cryptopals challenge 10
http://cryptopals.com/sets/2/challenges/10
------------------
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a
block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext
block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
(verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise
to combine them.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

This program is a little rough around the edges
almost all work is done in main()

main() reads the input file block-by-block, processes the block (encryption/decryption), and
writes the block out to the output file

When decrypting, the input file *must* be the raw cipher-text
to decrypt the challenge file (10.txt), the python3 script 'b64decoder.py' should first be used to
remove the base 64 encoding.
*/
package main

import (
	"../utils"
	"bufio"
	"crypto/aes"
	"fmt"
	"io"
	"os"
)

// program usage
const USAGE = "This program can encrypt and decrypt a file in AES CBC mode.\n\n" +
	"USAGE: ./challenge10 [mode] [key] [infile] [outfile]" +
	"\n\t[mode]     - 'encrypt' or 'decrypt'" +
	"\n\t[key]      - key stream to use" +
	"\n\t[infile]   - input file" +
	"\n\t[outfile]  - output file"

// main loadpoint
func main() {

	// check argument count, if fail print USAGE
	args := os.Args[1:]
	if len(args) != 4 {
		fmt.Println(USAGE)
		return
	}

	// interpret [mode] argument
	var mode int
	if args[0] == "encrypt" {
		mode = 0
	} else if args[0] == "decrypt" {
		mode = 1
	} else {
		fmt.Println(USAGE)
		return
	}

	// create AES cipher from [key]
	key := []byte(args[1])
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Could not create AES cipher:", err)
		return
	}

	// open [infile]
	inFile, err := os.Open(args[2])
	if err != nil {
		fmt.Println("Could not open input file:", err)
		return
	}
	defer inFile.Close()
	reader := bufio.NewReader(inFile)

	// create [outfile]
	outFile, err := os.Create(args[3])
	if err != nil {
		fmt.Println("Could not create output file:", err)
		return
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)

	// do operations
	IV := make([]byte, aesCipher.BlockSize()) // IV
	switch mode {
	case 0: // CBC encrypt mode
		inBlock := make([]byte, aesCipher.BlockSize())       // plain text read from file
		outBlock := IV                                       // output of AES encrypt
		paddedBlock := make([]byte, aesCipher.BlockSize()*2) // block used for padding when pad is full block size

		// process plaintext file
		done := false
		for !done {

			// read a block of bytes
			count, err := reader.Read(inBlock)
			if err == io.EOF {
				inBlock = utils.Pad(aesCipher.BlockSize(), inBlock[0:count])
				copy(paddedBlock, inBlock)
				done = true
			} else if err != nil {
				panic(err)
			}

			// if full count was not read, assume EOF
			if count < aesCipher.BlockSize() {
				inBlock = utils.Pad(aesCipher.BlockSize(), inBlock[0:count])
				copy(paddedBlock, inBlock)
				done = true
			}

			// E(pt ^ ct-1) = ct
			inBlock = utils.Xor(inBlock[:16], outBlock)
			aesCipher.Encrypt(outBlock, inBlock)
			if _, err := writer.Write(outBlock); err != nil {
				panic(err)
			}

			// if padding was full block, encrypt the final pad block and write to file
			if done && len(paddedBlock) > aesCipher.BlockSize() {
				inBlock = utils.Xor(paddedBlock[16:], outBlock)
				aesCipher.Encrypt(outBlock, inBlock)
				if _, err := writer.Write(outBlock); err != nil {
					panic(err)
				}
			}
		}
		writer.Flush()
		break

	case 1: // CBC decrypt mode
		inBlock := make([]byte, aesCipher.BlockSize())  // cipher text read from file
		outBlock := make([]byte, aesCipher.BlockSize()) // output of decrypt (pt ^ ct-1)
		cipherBlock := IV                               // previous cipher text block (ct-1)

		// processes cipher text file
		done := false
		for !done {

			// read a block of bytes
			_, err := reader.Read(inBlock)
			if err != nil {
				panic(err)
			}

			// peek ahead to identify the end of file
			_, err = reader.Peek(aesCipher.BlockSize() + 1)
			if err == io.EOF {
				done = true
			}

			// D(ct) = pt ^ ct-1
			aesCipher.Decrypt(outBlock, inBlock)
			outBlock = utils.Xor(cipherBlock, outBlock)
			copy(cipherBlock, inBlock)

			// remove padding if end of file as been found
			if done {
				outBlock, _ = utils.UnPad(outBlock)
			}

			// write out plaintext block
			if _, err := writer.Write(outBlock); err != nil {
				panic(err)
			}
		}
		writer.Flush()
		break
	}
}
