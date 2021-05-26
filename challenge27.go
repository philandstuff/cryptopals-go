package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

type C27Thing struct {
	key         [16]byte
	blockCipher cipher.Block
}

func NewC27Thing() *C27Thing {
	var key [16]byte
	rand.Read(key[:])
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return &C27Thing{key: key, blockCipher: cipher}
}

func (c27 *C27Thing) EncryptWithUserData(userData string) []byte {
	fullString := "comment1=cooking%20MCs;userdata=" + url.QueryEscape(userData) + ";comment2=%20like%20a%20pound%20of%20bacon"
	buf := []byte(fullString)
	buf = Pkcs7pad(buf, c27.blockCipher.BlockSize())

	// using the key as the IV! naughty!
	enc := NewCBCEncrypter(c27.blockCipher, c27.key[:])
	enc.CryptBlocks(buf, buf)
	return buf
}

func (c27 *C27Thing) DecryptAndCheckForAdmin(cipherText []byte) (bool, error) {
	dec := NewCBCDecrypter(c27.blockCipher, c27.key[:])
	plainText := make([]byte, len(cipherText))
	dec.CryptBlocks(plainText, cipherText)
	for _, b := range plainText {
		if b&0x80 != 0 {
			return false, fmt.Errorf("String %x was not valid ASCII", plainText)
		}
	}
	if strings.Contains(string(plainText), ";admin=true;") {
		return true, nil
	}
	return false, nil
}
