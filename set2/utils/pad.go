package utils

import (
	"bytes"
	"errors"
)

// Pad pads a byte buffer using the PKCS#7 schema
// and returns the padded byte array
func Pad(blockSize int, bytes1 []byte) []byte {

	// generate the pad size
	pad := byte(blockSize - (len(bytes1) % blockSize))

	// make a byte buffer and grow it
	byteBuffer := bytes.NewBuffer(bytes1)
	byteBuffer.Grow(int(pad))

	// write the pad to the buffer until the buffer is full
	for i := 0; i < int(pad); i++ {
		byteBuffer.WriteByte(pad)
	}

	return byteBuffer.Bytes()
}

// UnPad removes the pad from a padded byte array using the PKCS#7 schema
// and returns the unpadded byte array
func UnPad(bytes1 []byte) ([]byte, error) {

	// valid pad
	if !ValidatePad(bytes1) {
		return nil, errors.New("invalid padding")
	}

	// determine byte and pad length
	bytesLen := len(bytes1)
	padSize := int(bytes1[bytesLen-1])

	// if pad > length something is wrong
	if padSize > bytesLen {
		return bytes1, nil
	}

	// trim off pad
	bytes2 := bytes1[:bytesLen-padSize]
	return bytes2, nil
}

// UnPad removes the pad from a padded byte array using the PKCS#7 schema
// and returns the unpadded byte array
func ValidatePad(bytes1 []byte) bool {

	bytesLen := len(bytes1)
	padSize := int(bytes1[bytesLen-1])

	for i := 2; i <= padSize; i++ {
		if int(bytes1[bytesLen-i]) != padSize {
			return false
		}
	}

	return true
}
