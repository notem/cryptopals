/*
Solution to cryptopals challenge 11
http://cryptopals.com/sets/2/challenges/11

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-09
*/
package main

import (
	"math/rand"
	"time"
	"../utils"
	"os"
	"fmt"
)

// program usage
const USAGE = "This program will encrypt provided data under either CBC or ECB using a random key, and will\n" +
	"attempt to identify (knowing only the cipher text and block size) which AES mode was used.\n" +
	"This program is only accurate for plaintext with repeating blocks.\n\n" +
	"USAGE: ./challenge11 [data]" +
	"\n\t[data] - a string of data"

// main loadpoint
func main() {
	// check argument count, if fail print USAGE
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Println(USAGE)
		return
	}

	// seed rand
	rand.Seed(time.Now().UnixNano())

	// generate the size of the prefix and suffix data
	prefixSize := rand.Int()%11
	if prefixSize < 5 { prefixSize += 5}
	suffixSize := rand.Int()%11
	if suffixSize < 5 { suffixSize += 5}

	prefix := utils.RandomByteArray(prefixSize)		// prefix data
	suffix := utils.RandomByteArray(suffixSize)		// suffix data
	input := []byte(args[0])						// user input as byte array

	data := prefix						// set prefix
	for i:=0; i<len(input); i++ { 		// add real data to prefix byte by byte
		data = append(data, input[i])
	}
	for i:=0; i<len(suffix); i++ {		// add suffix byte by byte
		data = append(data, suffix[i])
	}

	// random encrypt data with blocksize of 16
	crypt := utils.RandomEncrypt(16, data)
	fmt.Printf("=> %q\n", crypt)

	if utils.DetectECB(16, crypt) {
		fmt.Println("==> detected ECB")
	} else {
		fmt.Println("==> did not detect ECB")
	}

}
