/*
Solution to cryptopals challenge 13
http://cryptopals.com/sets/2/challenges/13

author: Nate Mathews, njm3308@rit.edu
date: 2017-10-14
*/
package main

import (
	"os"
	"fmt"
	"../utils"
)

// program usage
const USAGE = "This program will encrypt provided data under either CBC or ECB using a random key, and will\n" +
	"attempt to identify (knowing only the cipher text and block size) which AES mode was used.\n" +
	"This program is only accurate for plaintext with repeating blocks.\n\n" +
	"USAGE: ./challenge11 [data]" +
	"\n\t[data] - a string of data"

// main loadpoint
func main() {

	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Println(USAGE)
		return
	}

	// create a user's profile
	aesKey := []byte("YELLOW SUBMARINE")
	crypt := CreateProfile(args[0], aesKey)
	fmt.Println("=>", DecryptProfile(crypt, aesKey))

	// compromise the system
	fmt.Println("===> Getting admin role. . .")
	crypt = Escalate(crypt)
	fmt.Println("=>", DecryptProfile(crypt, aesKey))
}


// gain administrative role using only the create profile function as an oracle
func Escalate(crypt string) (string) {
	return crypt
}


// create an encrypted user profile
func CreateProfile(email string, aesKey []byte) (string) {

	// generate the user profile map
	dict := make(map[string]string)
	dict["email"] = utils.Sanitize(email)
	dict["uid"] = "10"
	dict["role"] = "user"

	// serialize the profile and encrypt it under ECB
	serialized := utils.SerializeParameter(dict)
	crypt := utils.ECBEncrypt([]byte(serialized), aesKey)
	return string(crypt)
}

// decrypts a serialized and encrypted user profile
func DecryptProfile(crypt string, aesKey []byte) (string) {
	data := utils.ECBDecrypt([]byte(crypt), aesKey)
	return string(data)
}
