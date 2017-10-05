/*
Solution to cryptopals challenge 9
http://cryptopals.com/sets/2/challenges/9

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-5
*/
package main

import (
	"os"
	"fmt"
	"strconv"
	"bytes"
	"encoding/binary"
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
	stringAsBytes := bytes.NewBufferString(args[1])

	stringBuffer := PadBuffer(blockSize, stringAsBytes)

	// printout padded string
	fmt.Printf("%q\n", stringBuffer)
}


// PadBuffer pads a byte buffer using the PKCS#7 schema
// and returns the padded buffer
func PadBuffer(blockSize int, stringBuffer *bytes.Buffer) (*bytes.Buffer) {

	// find the size of the last block and generate the PadBuffer
	lastBlock := stringBuffer.Len() % blockSize
	padUInt := uint16(blockSize-(lastBlock%blockSize))
	pad := make([]byte, 2)
	binary.BigEndian.PutUint16(pad, padUInt)

	// grow the buffer and write the PadBuffer until block is full
	stringBuffer.Grow(blockSize - lastBlock)
	for i := 0; i < blockSize-lastBlock; i++ {
		stringBuffer.Write(pad[1:])
	}

	return stringBuffer
}


