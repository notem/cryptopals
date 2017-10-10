package utils

import (
	"crypto/aes"
	"math"
	"math/rand"
)

// generates a pseudo-random byte array
// rand should be seeded before calling this function
func RandomByteArray(size int) ([]byte) {

	key := make([]byte, size)
	for i:=0; i<size; i++ {
		key[i] = byte(rand.Int())
	}
	return key
}

// encrypt byte data using a random key in either ECB or CBC mode (chosen pseudo-randomly)
// seed rand before using this function
func RandomEncrypt(blockSize int, data []byte) ([]byte) {

	mode := rand.Int()%2				// 0 is CBC, 1 is ECB
	data = Pad(blockSize, data)	// pad the data
	crypt := make([]byte, len(data))	// encrypted byte array storage

	// create the AES cipher with a pseudo-random key
	key := RandomByteArray(blockSize)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// do encryption
	if mode == 0 {
		// CBC mode, encrypt the first block
		IV := RandomByteArray(blockSize)
		cipher.Encrypt(crypt[0:blockSize], Xor(IV, data[0:blockSize]))

		// encrypt remaining blocks
		for i:=blockSize; i<len(data); i+=blockSize {
			cipher.Encrypt(crypt[i:i+blockSize], Xor(crypt[i-blockSize:i], data[i:i+blockSize]))
		}
	} else {
		// ECB mode, encrypt each block in data
		for i:=0; i<len(data); i+=blockSize {
			cipher.Encrypt(crypt[i:i+blockSize], data[i:i+blockSize])
		}
	}
	return crypt
}

// an oracle function which attempts to detect if the mode used to encrypt a cipher text was ECB
// responds most effectively when the underlying plaintext has repeating blocks
func ECBOracle(blockSize int, ct []byte) (bool) {

	topRank := 0	// rank is the highest count of repeating blocks for a tested offset

	// determine rank for each offset up to blockSize
	for i:=0; i<blockSize; i++ {
		// unique block counts are saved as strings, int pairs in a map
		blockCount := make(map[string]int)

		// enumerate through blocks and save in map
		for j:=i; j<=len(ct)-blockSize; j+=blockSize {
			blockCount[string(ct[j:j+blockSize])] += 1
		}

		// determine rank for test
		rank := 0
		for block := range blockCount {
			if blockCount[block] > 1 {
				rank += blockCount[block]-1
			}
		}

		// update top rank
		if rank > topRank { topRank = rank }
	}

	threshold := 0
	// increase threshold for longer data sizes
	if float64(len(ct)) > math.Sqrt(math.Pow(2,float64(blockSize))) {
		threshold = 1
	}

	// compare rank to threshold
	return topRank > threshold
}
