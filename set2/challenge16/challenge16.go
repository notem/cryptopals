/*
Solution to cryptopals challenge 16
http://cryptopals.com/sets/2/challenges/16
------------------
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string: "comment1=cooking%20MCs;userdata=",
and append the string: ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt,
split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will
generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

Input sanitization removes ';' and '=' characters, rather than escape them.

To corrupt the cipher text in such a way that the plaintext include the string ';admin=true'
we need only to insure that we inject user input which, when XOR'ed with another byte array,
produces ';admin=true'

If we XOR our bytes into the cipher-text block preceding the block which contains our malicious input,
we can induce a fault which will result in our malicious input getting XOR'ed with our fault-inducing
byte array.

To do this successfully, we must know the location in which our malicious input will appear in the cipher-text.
This requires knowledge of the length of the string which is prepended to our input.
For this solution, I assume the length of the string is known by the attacker.
*/
package main

import (
	"../utils"
	"fmt"
	"regexp"
)

var (
	prefix    = "comment1=cooking%20MCs;userdata="
	suffix    = ";comment2=%20like%20a%20pound%20of%20bacon"
	blockSize = 16
	IV        = utils.RandomByteArray(blockSize)
	aesKey    = utils.RandomByteArray(blockSize)
)

// main loadpoint
func main() {
	Escalate()
}

// adds a prefix and suffix string to the user supplied input, encrypts under an unknown key
// and IV, then returns the encrypted text
func CBCOracle(input []byte) []byte {

	input = []byte(regexp.MustCompile("[;=]").ReplaceAllString(string(input), "")) // sanitize the input
	data := append(append([]byte(prefix), input...), []byte(suffix)...)            // sandwich input between prefix and suffix
	crypt, err := utils.CBCEncrypt(data, aesKey, IV)                               // do encryption
	if err != nil {
		panic(err)
	}
	return crypt
}

// a simple function which returns true if there exists an 'admin=true' k=v pair
// in the decrypted and deserialized input
func EscalationOracle(crypt []byte) bool {

	data, err := utils.CBCDecrypt(crypt, aesKey, IV) // decrypt the parameter string
	if err != nil {
		panic(err)
	}

	dict := utils.DeserializeParameters(string(data), ";") // deserialize the string into a map object

	// attempt to retrieve "admin"
	if value, found := dict.Get("admin"); found {
		return value == "true"
	}
	return false
}

// attempts to insert the 'admin=true' k,v pair into an encrypted parameters string of structure k=v;
// this solution requires knowledge of the length of the prefix data
func Escalate() {

	boundary := 32 // index of the block boundary we are interested in
	count := 0     // count of arbitrary bytes required to pad to block boundary

	// create the user content block, and bytes to xor into the block
	// necessary to yield the plaintext of ";admin=true"
	magic := ":admin<true"
	xor := []byte{1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// query the CBC oracle function with the malicious input
	crypt := CBCOracle(append(make([]byte, count), []byte(magic)...))

	// create the fault in the cipher-text block preceding our malicious input
	xor = utils.Xor(crypt[boundary-blockSize:boundary], xor)                             // create the faulty ct block
	evilCrypt := append(append(crypt[:boundary-blockSize], xor...), crypt[boundary:]...) // slice in the faulty block

	// use the admin=true oracle to identify if success was had
	if EscalationOracle(evilCrypt) {
		fmt.Println("Got admin access!")
	} else {
		fmt.Println("Failed to get admin access!")
	}
}
