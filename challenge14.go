package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"log"
	"math/rand"
)

func Challenge14EncryptionOracle() func(userinput []byte) []byte {
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
		prefixSize := rand.Intn(16)
		buf := make([]byte, prefixSize+len(userinput)+len(fixedSuffix))
		rand.Read(buf)
		copy(buf[prefixSize:], userinput)
		copy(buf[prefixSize+len(userinput):], fixedSuffix)
		buf = Pkcs7pad(buf, encrypter.BlockSize())
		encrypter.CryptBlocks(buf, buf)
		return buf
	}
}

func Challenge14DetectBlockSizeFromOracle(encryptionOracle func([]byte) []byte) int {
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

func Challenge14DecryptECBFromOracle(blockSize int, oracle func([]byte) []byte) []byte {
	knownText := []byte{}
	// first blocksize bytes, we need to prefill with zeros
DECRYPT_BYTE:
	for i := 0; ; i++ {
		testBlock := make([]byte, blockSize)
		if i < blockSize {
			copy(testBlock[blockSize-i-1:], knownText)
		} else {
			copy(testBlock, knownText[len(knownText)-blockSize+1:])
		}
		// we prepend two blocks of "YELLOW SUBMARINE" to detect if we
		// have aligned ourselves appropriately
		testData := append(bytes.Repeat([]byte("YELLOW SUBMARINE"), 2), bytes.Repeat(testBlock, 256)...)
		testData = append(testData, make([]byte, blockSize-(i%blockSize)-1)...)

		for j := 0; j < 256; j++ {
			testData[(j+2)*blockSize+blockSize-1] = byte(j)
		}
		// The difference with Challenge 12 is that there is a random
		// prefix added within the oracle. This means we don't know
		// where the block boundaries will end up.  We fix this by
		// just repeatedly calling the oracle until we get the block
		// alignment we want.
		//
		// This algorithm is not 100% reliable. I'm not sure why but
		// it seems to get confused sometimes.
		for try := 0; try < 100; try++ {
			cipherText := oracle(testData)

			yellowSubmarine := DetectRepeatedBlock(cipherText)
			if yellowSubmarine == nil {
				continue // not find, try again
			}
			yellowSubmarine1 := bytes.Index(cipherText, yellowSubmarine)
			yellowSubmarine2 := bytes.Index(cipherText[yellowSubmarine1+blockSize:], yellowSubmarine)
			if yellowSubmarine2 != 0 {
				continue // the repeated block wasn't our yellowSubmarine sentinel
			}
			// strip all the ciphertext up to and including the yellow
			// submarine sentinel
			cipherText = cipherText[yellowSubmarine1+2*blockSize:]
			repeatedBlock := DetectRepeatedBlock(cipherText)
			if repeatedBlock == nil {
				continue // didn't find it, try again
			}

			foundBlock := bytes.Index(cipherText, repeatedBlock) / blockSize
			targetBlockDist := bytes.Index(cipherText[foundBlock*blockSize+blockSize:], repeatedBlock) / blockSize
			if foundBlock == -1 {
				panic("can't happen?")
			}
			if targetBlockDist == -1 {
				log.Fatalf("didn't find a second block")
			}
			decryptedByte := (256 - (targetBlockDist + 1)) + len(knownText)/blockSize
			if foundBlock+targetBlockDist-len(knownText)/blockSize != 255 {
				// we've detected something weird; ignore it and try again
				continue
			}
			knownText = append(knownText, byte(decryptedByte))
			// log.Fatalf("decrypted byte %x, foundBlock %d, targetBlockDist %x\nrepeatedBlock %x\ncipherText %x", decryptedByte, foundBlock, targetBlockDist, repeatedBlock, cipherText)
			continue DECRYPT_BYTE
		}
		break
	}
	return knownText
}
