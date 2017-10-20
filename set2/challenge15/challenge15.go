/*
Solution to cryptopals challenge 15
http://cryptopals.com/sets/2/challenges/15
------------------
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception
on bad padding.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

This program is non-interactive, and is only intended to showcase that the UnPad function works correctly
The UnPad function can be found in 'pad.go' of the utils package
*/
package main

import (
	"../utils"
	"fmt"
)

var (
	valid      = "ICE ICE BABY\x04\x04\x04\x04"
	invalidOne = "ICE ICE BABY\x05\x05\x05\x05"
	invalidTwo = "ICE ICE BABY\x01\x02\x03\x04"
)

// main loadpoint
func main() {

	// attempt to un-pad the string with valid padding
	_, err := utils.UnPad([]byte(valid))
	if err == nil {
		fmt.Printf("%q has valid padding!\n", valid)
	} else {
		fmt.Printf("%q does not have valid padding!\n", valid)
	}

	// attempt to un-pad the first string with invalid padding
	_, err = utils.UnPad([]byte(invalidOne))
	if err == nil {
		fmt.Printf("%q has valid padding!\n", invalidOne)
	} else {
		fmt.Printf("%q does not have valid padding!\n", invalidOne)
	}

	// attempt to un-pad the second string with invalid padding
	_, err = utils.UnPad([]byte(invalidTwo))
	if err == nil {
		fmt.Printf("%q has valid padding!\n", invalidTwo)
	} else {
		fmt.Printf("%q does not have valid padding!\n", invalidTwo)
	}
}
