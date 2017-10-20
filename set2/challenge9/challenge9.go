/*
Solution to cryptopals challenge 9
http://cryptopals.com/sets/2/challenges/9
------------------
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we
almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple
of the blocksize. The most popular padding scheme is called PKCS#7.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

the padding functions can be found in the utils package
this program is useful only for testing the padding function

*/
package main

import (
	"../utils"
	"fmt"
	"os"
	"strconv"
)

// program usage
const USAGE = "This program will PadBuffer a string using the PKCS#7 scheme.\n\n" +
	"USAGE: ./challenge9 [block_size] [unpadded_string]" +
	"\n\t[block_size]      - the size of each block in bytes" +
	"\n\t[unpadded_string] - the string to PadBuffer to block_size"

// load point for the program
func main() {

	// check argument count, if fail print USAGE
	args := os.Args[1:]
	if len(args) != 2 {
		fmt.Println(USAGE)
		return
	}

	// get the block size
	blockSize, err := strconv.Atoi(args[0])
	if err != nil || blockSize <= 0 || blockSize > 255 {
		fmt.Println("Invalid blocksize!")
		return
	}

	// convert string argument into a byte buffer
	stringAsBytes := []byte(args[1])
	stringAsBytesPadded := utils.Pad(blockSize, stringAsBytes)

	// printout padded string
	fmt.Printf("%q\n", stringAsBytesPadded)
}
