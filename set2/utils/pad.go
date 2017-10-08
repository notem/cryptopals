package utils

import (
	"bytes"
	"encoding/binary"
)

// Pad pads a byte buffer using the PKCS#7 schema
// and returns the padded buffer
func Pad(blockSize int, stringBuffer *bytes.Buffer) *bytes.Buffer {

	// find the size of the last block
	lastBlock := stringBuffer.Len() % blockSize

	// generate the pad size
	padUInt := uint16(blockSize - (lastBlock % blockSize))
	pad := make([]byte, 2)
	binary.BigEndian.PutUint16(pad, padUInt)

	// grow the buffer and write the Pad until block is full
	stringBuffer.Grow(blockSize - lastBlock)
	for i := 0; i < blockSize-lastBlock; i++ {
		stringBuffer.Write(pad[1:])
	}

	return stringBuffer
}

