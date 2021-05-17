package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"math/rand"
)

type C17Thing struct {
	blockCipher cipher.Block
}

var c17Cookies = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func NewC17Thing() *C17Thing {
	var key [16]byte
	rand.Read(key[:])
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return &C17Thing{blockCipher: cipher}
}

func (c17 *C17Thing) GetEncryptedCookie() []byte {
	i := rand.Intn(10)
	buf, err := base64.StdEncoding.DecodeString(c17Cookies[i])
	if err != nil {
		panic("can't happen")
	}
	buf = Pkcs7pad(buf, c17.blockCipher.BlockSize())
	var iv [16]byte
	rand.Read(iv[:])
	enc := NewCBCEncrypter(c17.blockCipher, iv[:])
	enc.CryptBlocks(buf, buf)
	return append(iv[:], buf...)
}

func (c17 *C17Thing) IsValidPadding(cipherText []byte) bool {
	iv := cipherText[0:16]
	cipherText = cipherText[16:]
	dec := NewCBCDecrypter(c17.blockCipher, iv)
	plainText := make([]byte, len(cipherText))
	dec.CryptBlocks(plainText, cipherText)

	_, err := TrimPkcs7Padding(plainText)
	return err == nil
}

// attack code

func C17PaddingOracleAttack(cipherText []byte, c17 *C17Thing) string {
	knownText := make([]byte, len(cipherText)-16)
	for block := 0; block < (len(cipherText)/16)-1; block++ {
		testText := make([]byte, 32)
		copy(testText, cipherText[block*16:])
		for j := 1; j <= 16; j++ {
			origByte := testText[16-j]
			for i := 0; i < 256; i++ {
				testText[16-j] = origByte ^ byte(i)
				if c17.IsValidPadding(testText) {
					// make sure it wasn't a fluke
					if j != 16 {
						testText[16-j-1] ^= 0x1
						if !c17.IsValidPadding(testText) {
							testText[16-j-1] ^= 0x1
							continue
						}
						testText[16-j-1] ^= 0x1
					}
					knownText[block*16+16-j] = byte(i) ^ byte(j)
					// increment the padding block
					for k := 16 - j; k < 16; k++ {
						testText[k] ^= byte(j) ^ byte(j+1)
					}
					break
				}
			}
		}
	}
	unpadded, err := TrimPkcs7Padding(knownText)
	if err == nil {
		return string(unpadded)
	}
	return string(knownText)
}
