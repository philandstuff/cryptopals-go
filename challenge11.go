package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"log"
	"math/rand"
)

// Challenge 11 is weird enough to deserve its own file

func Challenge11DetectECB(encryptionOracle func(userinput []byte) []byte) bool {
	testData := bytes.Repeat([]byte{0}, 16*3-1)
	cipherText := encryptionOracle(testData)
	block := DetectRepeatedBlock(cipherText)
	return block != nil
}

func Challenge11EncryptRandomData(userinput []byte) []byte {
	prefix := make([]byte, rand.Intn(5)+5)
	suffix := make([]byte, rand.Intn(5)+5)
	var key [16]byte
	var iv [16]byte
	rand.Read(prefix)
	rand.Read(suffix)

	rand.Read(key[:])
	rand.Read(iv[:])

	chooseECB := rand.Intn(2) == 0
	if chooseECB {
		log.Print("Chose ECB")
	} else {
		log.Print("Chose CBC")
	}

	return Challenge11EncryptData(chooseECB, key[:], iv[:], prefix, suffix)(userinput)
}

func Challenge11EncryptData(chooseECB bool, key, iv []byte, prefix, suffix []byte) func(userinput []byte) []byte {
	cph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return func(userinput []byte) []byte {
		buf := make([]byte, len(prefix)+len(userinput)+len(suffix))
		copy(buf, prefix)
		copy(buf[len(prefix):], userinput)
		copy(buf[len(prefix)+len(userinput):], suffix)

		var encrypter cipher.BlockMode
		if chooseECB {
			encrypter = NewECBEncrypter(cph)
		} else {
			encrypter = NewCBCEncrypter(cph, iv)
		}

		buf = Pkcs7pad(buf, 16)

		encrypter.CryptBlocks(buf, buf)
		return buf
	}
}
