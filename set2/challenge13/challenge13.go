/*
Solution to cryptopals challenge 13
http://cryptopals.com/sets/2/challenges/13
------------------
Write a k=v parsing routine, as if for a structured cookie.

Now write a function that encodes a user profile in that format, given an email address.

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them,
whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

1. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
2. Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the
ciphertexts themselves, make a role=admin profile.
------------------

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-20
notes:

the solution for this set introduces a new dependency on the 'ordered_map' package by GitHub user
cevaris: https://github.com/cevaris/ordered_map

the functions used to parse k=v tokens from a string into a structured object can be found in
'serialize.go' of the utils package

the solution used assumes knowledge of the structure of the string (ie. we know the parameters string
ends with 'role=user')

the program is interactive. The user may supply asked to supply an email string of a particular length

with some additional work this program could be modified to allow for greater flexibility in the
character length required for the email string used to exploit the ECB encryption system
*/
package main

import (
	"../utils"
	"fmt"
	"github.com/cevaris/ordered_map"
	"os"
)

// program usage
const USAGE = "This program contains a user profile creation oracle which returns encrypted strings under an unknown key with AES-ECB.\n" +
	"The only argument that is supplied by the user is an email address.\n" +
	"This program exploits the lack of integrity verification to modify the role of the created user.\n" +
	"Usage: ./challenge13 [email]" +
	"\n\t[email] - email string"

// secret key used by the oracle
var aesKey = []byte("YELLOW SUBMARINE")

// main loadpoint
func main() {

	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Println(USAGE)
		return
	}

	// this is not necessarily true, if my code was more robust there could exist more flexibility
	// in allowed email lengths
	if len(args[0]) != FindInputLength()+4 {
		fmt.Println("Email string length must be", FindInputLength()+4, "characters long for exploitation!")
		return
	}

	// create a user's profile
	crypt := CreateProfile(args[0])
	fmt.Println("===> Making user profile. . .")
	fmt.Printf("=> %v\n", DecryptProfile(crypt, aesKey))

	// compromise the system
	fmt.Println("===> Making admin profile. . .")
	crypt = Escalate(args[0])
	fmt.Printf("=> %v\n", DecryptProfile(crypt, aesKey))
}

// finds the number of characters required to create a new block
// of the encrypted user profile string
func FindInputLength() int {

	// discover the size of user-input required to create a new block
	size := len(CreateProfile(string(make([]byte, 0))))
	data := make([]byte, 1)
	count := 1
	for true {
		dif := len(CreateProfile(string(data))) - size
		if dif > 0 {
			return count
		} else {
			data = append(data, byte(0))
			count++
		}
	}
	return -1
}

// gain administrative role using only the create profile function as an oracle
// this function does assume absolute knowledge of the cipher-text's structure and plain-text
func Escalate(email string) string {

	// detect the block size of the cipher
	blockSize := utils.DetectBlockSize(CreateProfileBytes)
	count := FindInputLength()

	// create a profile which pushes the role variable onto an isolated block
	a := CreateProfile(email) // email=nanananana | nan&uid=10&role= | user[pad]

	// create a profile which isolates the plaintext 'admin...' onto a block
	tmp := append(make([]byte, count+1), utils.Pad(int(blockSize), []byte("admin"))...)
	b := CreateProfile(string(tmp)) // email=nanananana | admin[pad] | &uid=10&role=use | r[pad]

	// slice together desired blocks
	crypt := append([]byte(a)[:blockSize*2], []byte(b)[blockSize:]...)
	return string(crypt)
}

// wrapper to create compatibility between my DetectBlockSize function and
// CreateProfileBytes function
func CreateProfileBytes(data []byte) []byte {

	return []byte(CreateProfile(string(data)))
}

// create an encrypted user profile
func CreateProfile(email string) string {

	// generate the user profile map
	dict := ordered_map.NewOrderedMap()
	dict.Set("email", utils.Sanitize(email))
	dict.Set("uid", "10")
	dict.Set("role", "user")

	// serialize the profile and encrypt it under ECB
	serialized := utils.SerializeParameter(dict, "&")
	crypt, err := utils.ECBEncrypt([]byte(serialized), aesKey)
	if err != nil {
		panic(err)
	}
	return string(crypt)
}

// decrypts a serialized and encrypted user profile
func DecryptProfile(crypt string, aesKey []byte) string {

	data, err := utils.ECBDecrypt([]byte(crypt), aesKey)
	if err != nil {
		panic(err)
	}
	return string(data)
}
