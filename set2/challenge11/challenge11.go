/*
Solution to cryptopals challenge 11
http://cryptopals.com/sets/2/challenges/11
------------------
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates
a random key and encrypts under it.

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half
(just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of
code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

The function used to generate the random AES key, the function used to randomly encrypt the input data,
and the function responsible for detecting ECB encrypted text can be found in the utils package

This program is simply a showcase of the aforementioned functions capabilities
*/
package main

import (
	"../utils"
	"fmt"
	"math/rand"
	"os"
	"time"
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

	rand.Seed(time.Now().UnixNano()) // (un-secure) rand seeding

	// generate the size of the prefix and suffix data
	prefixSize := rand.Int() % 11
	if prefixSize < 5 {
		prefixSize += 5
	} // fix values less than 5

	suffixSize := rand.Int() % 11
	if suffixSize < 5 {
		suffixSize += 5
	} // fix values less than 5

	prefix := utils.RandomByteArray(prefixSize) // create prefix data
	suffix := utils.RandomByteArray(suffixSize) // create suffix data
	input := []byte(args[0])                    // user input as byte array

	data := prefix                    // set prefix
	for i := 0; i < len(input); i++ { // add real data to prefix byte by byte
		data = append(data, input[i])
	}
	for i := 0; i < len(suffix); i++ { // add suffix byte by byte
		data = append(data, suffix[i])
	}

	// random encrypt data with blocksize of 16
	crypt, err := utils.RandomEncrypt(16, data)
	if err != nil {
		panic(err)
	}

	if utils.DetectECB(16, crypt) {
		fmt.Println("==> detected ECB")
	} else {
		fmt.Println("==> did not detect ECB")
	}
}
