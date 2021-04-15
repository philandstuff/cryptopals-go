package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
)

const fixedString = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

func Challenge12EncryptionOracle(key []byte) func(userinput []byte) []byte {
	cph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypter := NewECBEncrypter(cph)
	fixedSuffix, err := base64.StdEncoding.DecodeString(fixedString)
	if err != nil {
		panic(err)
	}
	return func(userinput []byte) []byte {
		buf := make([]byte, len(userinput)+len(fixedSuffix))
		copy(buf, userinput)
		copy(buf[len(userinput):], fixedSuffix)
		buf = Pkcs7pad(buf, encrypter.BlockSize())
		encrypter.CryptBlocks(buf, buf)
		return buf
	}
}

func DetectBlockSizeFromOracle(encryptionOracle func([]byte) []byte) int {
	buf := []byte{}
	size := len(encryptionOracle(buf))
	for len(buf) <= 128 {
		buf = append(buf, 0)
		newSize := len(encryptionOracle(buf))
		if newSize > size {
			return newSize - size
		}
	}
	panic("couldn't find block size")
}
