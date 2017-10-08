/*
Solution to cryptopals challenge 10
http://cryptopals.com/sets/2/challenges/10

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-07
*/
package main

import (
	"../utils"
	"os"
	"fmt"
	"crypto/aes"
	"bytes"
	"io"
	"bufio"
)

// main loadpoint
func main() {

	// program usage
	const USAGE = "This program will PadBuffer a string using the PKCS#7 scheme.\n\n" +
		"USAGE: ./challenge10 [mode] [key] [infile] [outfile]" +
		"\n\t[block_size]      - the size of each block in bytes" +
		"\n\t[unpadded_string] - the string to PadBuffer to block_size"

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
		fmt.Println("Could not create cipher:", err)
		return
	}

	// open [infile]
	inFile, err := os.Open(args[2])
	if err != nil {
		fmt.Println("Could not open input file:", err)
		return
	}
	reader := bufio.NewReader(inFile)

	// create [outfile]
	outFile, err := os.Create(args[3])
	if err != nil {
		fmt.Println("Could not create output file:", err)
		return
	}
	writer := bufio.NewWriter(outFile)

	// do operations
	IV := make([]byte, aesCipher.BlockSize()) // IV
	switch mode {
		case 0: // encrypt mode
			done := false
			inBlock := make([]byte, aesCipher.BlockSize())
			outBlock := IV
			for !done {
				// read a block of bytes
				_, err := reader.Read(inBlock)
				if err == io.EOF {
					// pad the block if EOF
					inBlock = utils.Pad(aesCipher.BlockSize(), bytes.NewBuffer(inBlock)).Bytes()
					done = true
				} else if err != nil {
					panic(err)
				}

				// E(pt ^ IV) = ct
				inBlock = utils.Xor(inBlock[:16], outBlock)
				aesCipher.Encrypt(outBlock, inBlock[:16])
				if _, err := writer.Write(outBlock); err != nil {
					panic(err)
				}

				// if padding was full block
				if done && len(inBlock) > aesCipher.BlockSize() {
					inBlock = utils.Xor(inBlock[:16], outBlock)
					aesCipher.Encrypt(outBlock, inBlock[:16])
					if _, err := writer.Write(outBlock); err != nil {
						panic(err)
					}
				}
			}
			writer.Flush()
			break

		case 1: // decrypt mode
			done := false
			inBlock := make([]byte, aesCipher.BlockSize())
			outBlock := make([]byte, aesCipher.BlockSize())
			cipherBlock := IV
			for !done {
				// read a block of bytes
				_, err := reader.Read(inBlock)
				if err == io.EOF {
					done = true
				} else if err != nil {
					panic(err)
				}

				// D(ct) = pt ^ IV
				aesCipher.Decrypt(outBlock, inBlock)
				outBlock = utils.Xor(cipherBlock, outBlock)
				copy(cipherBlock, inBlock)

				// remove padding
				if done {
					// determine padding size
					padSize := outBlock[len(outBlock)-1]
					if padSize == 0 {
						break
					}
					// trim off pad
					endIndex := len(outBlock)-int(padSize)
					outBlock = outBlock[:endIndex]
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
