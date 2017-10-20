package utils

import (
	"math/rand"
	"time"
)

// generates a pseudo-random byte array
func RandomByteArray(size int) []byte {

	rand.Seed(time.Now().UnixNano()) // (un-secure) seeding
	key := make([]byte, size)        // key array
	for i := 0; i < size; i++ {
		// make random bytes
		key[i] = byte(rand.Int())
	}
	return key
}

// xor together two same size byte arrays
func Xor(bytes1 []byte, bytes2 []byte) []byte {

	// if arrays not same size, return nil
	l := len(bytes1)
	if l != len(bytes2) {
		return nil
	}

	// do xor
	bytes3 := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes3[i] = bytes1[i] ^ bytes2[i]
	}
	return bytes3
}
