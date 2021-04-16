package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"log"
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

// returns (block size, hidden text size)
func DetectBlockSizeFromOracle(encryptionOracle func([]byte) []byte) (int, int) {
	buf := []byte{}
	size := len(encryptionOracle(buf))
	for len(buf) <= 128 {
		buf = append(buf, 0)
		newSize := len(encryptionOracle(buf))
		if newSize > size {
			return newSize - size, size - len(buf)
		}
	}
	panic("couldn't find block size")
}

func Challenge12DecryptECBFromOracle(blockSize int, unknownTextSize int, oracle func([]byte) []byte) []byte {
	knownText := make([]byte, 0, unknownTextSize)
	if blockSize > unknownTextSize {
		panic("unimplemented")
	}
	// first blocksize bytes, we need to prefill with zeros
	for i := 0; i < unknownTextSize; i++ {
		testBlock := make([]byte, blockSize)
		if i < blockSize {
			copy(testBlock[blockSize-i-1:], knownText)
		} else {
			copy(testBlock, knownText[len(knownText)-blockSize+1:])
		}
		testData := bytes.Repeat(testBlock, 256)
		testData = append(testData, make([]byte, blockSize-(i%blockSize)-1)...)

		for j := 0; j < 256; j++ {
			testData[j*blockSize+blockSize-1] = byte(j)
		}
		log.Printf("Encrypting: %x\n", testData)
		cipherText := oracle(testData)
		targetBlock := 256 + i/blockSize
		target := cipherText[targetBlock*blockSize : (targetBlock+1)*blockSize]
		log.Printf("Searching for: %x\n", target)
		log.Printf("In: %x", cipherText)
		decryptedByte := bytes.Index(cipherText, target) / blockSize
		if decryptedByte < 0 || decryptedByte >= 256 {
			log.Fatalf("Didn't expect %d. Decrypted so far: %x", decryptedByte, knownText)
		}
		knownText = append(knownText, byte(decryptedByte))
		log.Printf("Decrypted byte is %x", decryptedByte)
	}
	log.Printf("Decrypted so far %x", knownText)
	return knownText
}
