/*
Solution to cryptopals challenge 14
http://cryptopals.com/sets/2/challenges/14

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-19
*/
package main

import (
	"../utils"
	"regexp"
	"fmt"
)

var (
	prefix 	= "comment1=cooking%20MCs;userdata="
	suffix 	= ";comment2=%20like%20a%20pound%20of%20bacon"
	blockSize = 16
	IV 		= utils.RandomByteArray(blockSize)
	aesKey 	= utils.RandomByteArray(blockSize)
)

// main loadpoint
func main() {
	Escalate()
}

// adds a prefix and suffix string to the user supplied input, encrypts under an unknown key
// and IV, then returns the encrypted text
func CBCOracle(input []byte) ([]byte) {

	input = []byte(regexp.MustCompile("[;=]").ReplaceAllString(string(input), ""))
	data := append(append([]byte(prefix), input...), []byte(suffix)...)
	return utils.CBCEncrypt(data, aesKey, IV)
}

// a simple function which returns true if there exists an 'admin=true' k=v pair
// in the decrypted and deserialized input
func EscalationOracle(crypt []byte) (bool) {

	data := string(utils.CBCDecrypt(crypt, aesKey, IV))		// decrypt the parameter string
	dict := utils.DeserializeParameters(data, ";")		// deserialize the string into a map object

	// attempt to retrieve "admin"
	if value, found := dict.Get("admin"); found {
		return value == "true"
	}
	return false
}

// attempts to insert the 'admin=true' k,v pair into an encrypted parameters string of structure k=v;
func Escalate() {

	boundary := 32
	count := 0

	// create the user content block, and bytes to xor into the block
	// necessary to yield the plaintext of ";admin=true"
	magic := ":admin<true"
	xor := []byte{1,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0}

	// query the CBC oracle function with the malicious input
	crypt := CBCOracle(append(make([]byte,count), []byte(magic)...))

	// create the fault in the cipher-text block preceding our malicious input
	xor = utils.Xor(crypt[boundary-blockSize:boundary], xor)								// create the faulty ct block
	evilCrypt := append(append(crypt[:boundary-blockSize], xor...), crypt[boundary:]...)	// slice in the faulty block

	// use the admin=true oracle to identify if success was had
	if EscalationOracle(evilCrypt) {
		fmt.Println("Got admin access!")
	} else {
		fmt.Println("Failed to get admin access!")
	}
}
