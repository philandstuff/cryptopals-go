package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"strings"
)

func ParseKV(input string) map[string]string {
	out := map[string]string{}
	if len(input) == 0 {
		return out
	}
	log.Print(input)
	for _, field := range strings.Split(input, "&") {
		pieces := strings.SplitN(field, "=", 2)
		out[pieces[0]] = pieces[1]
	}
	return out
}

func ProfileFor(email string) string {
	splitpoint := strings.IndexAny(email, "=&")
	if splitpoint >= 0 {
		// ignore anything after = or & inclusive
		email = email[:splitpoint]
	}
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}

type C13Codec struct {
	b cipher.Block
}

func NewC13Codec(key []byte) *C13Codec {
	cph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &C13Codec{b: cph}
}

func (c *C13Codec) EncodeProfileFor(email string) []byte {
	enc := NewECBEncrypter(c.b)
	profile := ProfileFor(email)
	in := Pkcs7pad([]byte(profile), c.b.BlockSize())
	out := make([]byte, len(in))
	enc.CryptBlocks(out, in)
	return out
}

func (c *C13Codec) DecryptProfile(cipherText []byte) map[string]string {
	dec := NewECBDecrypter(c.b)
	plainText := make([]byte, len(cipherText))
	dec.CryptBlocks(plainText, cipherText)
	return ParseKV(string(TrimPkcs7Padding(plainText)))
}
