package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"net/url"
	"strings"
)

type C16Thing struct {
	blockCipher cipher.Block
}

func NewC16Thing() *C16Thing {
	var key [16]byte
	rand.Read(key[:])
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return &C16Thing{blockCipher: cipher}
}

func (c16 *C16Thing) EncryptWithUserData(userData string) []byte {
	fullString := "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userData) + ";comment2=%20like%20a%20pound%20of%20bacon"
	buf := []byte(fullString)
	buf = Pkcs7pad(buf, c16.blockCipher.BlockSize())
	// yeah, I should probably generate an IV, but I don't
	enc := NewCBCEncrypter(c16.blockCipher, bytes.Repeat([]byte{0}, 16))
	enc.CryptBlocks(buf, buf)
	return buf
}

func (c16 *C16Thing) DecryptAndCheckForAdmin(cipherText []byte) bool {
	dec := NewCBCDecrypter(c16.blockCipher, bytes.Repeat([]byte{0}, 16))
	plainText := make([]byte, len(cipherText))
	dec.CryptBlocks(plainText, cipherText)
	if strings.Contains(string(plainText), ";admin=true;") {
		return true
	}
	return false
}
