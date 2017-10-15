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

// encrypt data under AES ECB
func ECBEncrypt(data []byte, key []byte) ([]byte) {

	aesCipher, err := aes.NewCipher(key) // aes aesCipher
	if err != nil {
		panic(err)
	}

	blockSize := aesCipher.BlockSize() // block size
	data = Pad(blockSize, data)        // pad the data
	crypt := make([]byte, len(data))   // encrypted byte array storage

	// ECB mode, encrypt each block in data
	for i:=0; i<len(data); i+=blockSize {
		aesCipher.Encrypt(crypt[i:i+blockSize], data[i:i+blockSize])
	}

	// fully encrypted data
	return crypt
}

// decrypt data under AES ECB
func ECBDecrypt(crypt []byte, key []byte) ([]byte) {

	aesCipher, err := aes.NewCipher(key) // aes aesCipher
	if err != nil {
		panic(err)
	}

	blockSize := aesCipher.BlockSize() // block size
	data := make([]byte, len(crypt))   // data storage array

	// ECB mode, decrypt each block in data
	for i:=0; i<len(crypt); i+=blockSize {
		aesCipher.Decrypt(data[i:i+blockSize], crypt[i:i+blockSize])
	}

	// remove pad from the decrypted data and return
	data = UnPad(data)
	return data
}

// encrypt data under AES CBC
func CBCEncrypt(data []byte, key []byte, IV []byte) ([]byte) {

	aesCipher, err := aes.NewCipher(key) // aes aesCipher
	if err != nil {
		panic(err)
	}

	blockSize := aesCipher.BlockSize() // block size
	crypt := make([]byte, len(data))   // data storage array

	// CBC mode, encrypt the first block
	aesCipher.Encrypt(crypt[0:blockSize], Xor(IV, data[0:blockSize]))

	// encrypt remaining blocks
	for i:=blockSize; i<len(data); i+=blockSize {
		aesCipher.Encrypt(crypt[i:i+blockSize], Xor(crypt[i-blockSize:i], data[i:i+blockSize]))
	}

	return crypt
}

// decrypt data under AES CBC
func CBCDecrypt(crypt []byte, key []byte, IV []byte) ([]byte) {

	aesCipher, err := aes.NewCipher(key) // aes aesCipher
	if err != nil {
		panic(err)
	}

	blockSize := aesCipher.BlockSize() // block size
	data := make([]byte, len(crypt))   // data storage array

	// CBC mode, encrypt the first block
	aesCipher.Decrypt(data[0:blockSize], crypt[0:blockSize])
	data = append(data[0:blockSize], Xor(IV, data[0:blockSize])...)

	// encrypt remaining blocks
	for i:=blockSize; i<len(data); i+=blockSize {
		aesCipher.Decrypt(data[i:i+blockSize], crypt[i-blockSize:i])
		data = append(data[i:i+blockSize], Xor(crypt[i-blockSize:i], data[i:i+blockSize])...)
	}

	// remove pad from the decrypted data and return
	data = UnPad(data)
	return data
}

// encrypt byte data using a random key in either ECB or CBC mode (chosen pseudo-randomly)
// seed rand before using this function
func RandomEncrypt(keySize int, data []byte) ([]byte) {

	key := RandomByteArray(keySize)	// pseudo-random key

	// do encryption
	if rand.Int()%2 == 0 {
		return CBCEncrypt(data, key, RandomByteArray(aes.BlockSize))
	} else {
		return ECBEncrypt(data, key)
	}
}

// a function which attempts to detect if the mode used to encrypt a cipher text was ECB
// responds most effectively when the underlying plaintext has repeating blocks
func DetectECB(blockSize int, ct []byte) (bool) {

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

	// increase threshold for longer data sizes
	threshold := 0
	if float64(len(ct)) > math.Sqrt(math.Pow(2,float64(blockSize))) {
		threshold = 1 		// not a very adaptive method
	}

	// compare rank to threshold
	return topRank > threshold
}

// determine the block size for the ECBOracle
func DetectBlockSize(oracle func([]byte)[]byte) (uint) {

	size := len(oracle(make([]byte,0)))
	data := make([]byte,1)
	for true {
		dif := len(oracle(data)) - size
		if dif > 0 {
			return uint(dif)
		} else {
			data = append(data, byte(0))
		}
	}
	return 0		// no valid block size found
}
