package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"log"
	"math/rand"
)

const c12FixedString = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

func Challenge12EncryptionOracle() func(userinput []byte) []byte {
	var secretKey [16]byte
	rand.Read(secretKey[:])
	cph, err := aes.NewCipher(secretKey[:])
	if err != nil {
		panic(err)
	}
	encrypter := NewECBEncrypter(cph)
	fixedSuffix, err := base64.StdEncoding.DecodeString(c12FixedString)
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
		cipherText := oracle(testData)

		repeatedBlock := DetectRepeatedBlock(cipherText)
		if repeatedBlock == nil {
			log.Fatalf("failed to find repeated block after decrypting %s\ntestData %x\ncipherText %x", string(knownText), testData, cipherText)
		}

		foundBlock := bytes.Index(cipherText, repeatedBlock) / blockSize
		targetBlockDist := bytes.Index(cipherText[foundBlock*blockSize+blockSize:], repeatedBlock) / blockSize
		if foundBlock == -1 {
			panic("can't happen?")
		}
		if targetBlockDist == -1 {
			log.Fatalf("didn't find a second block; detected block %x; ciphertext %x", repeatedBlock, cipherText)
		}
		decryptedByte := (256 - (targetBlockDist + 1)) + len(knownText)/blockSize

		if decryptedByte < 0 || decryptedByte >= 256 {
			log.Fatalf("Didn't expect %d. Decrypted so far: %x", decryptedByte, knownText)
		}
		knownText = append(knownText, byte(decryptedByte))
	}
	return knownText
}
