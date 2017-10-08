package utils

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

