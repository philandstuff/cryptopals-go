package cryptopals_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/philandstuff/cryptopals-go"
)

var genBlock = gen.SliceOfN(16, gen.UInt8())

func TestECBDecryptEncrypt(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("ECB encrypt/decrypt is a no-op", prop.ForAll(
		func(key []byte, blocks [][]byte) bool {
			cipher, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			data := []byte{}
			for _, block := range blocks {
				data = append(data, block...)
			}
			encrypter := cryptopals.NewECBEncrypter(cipher)
			decrypter := cryptopals.NewECBDecrypter(cipher)
			actual := make([]byte, len(data))
			encrypter.CryptBlocks(actual, data)
			decrypter.CryptBlocks(actual, actual)
			return bytes.Equal(actual, data)
		},
		genBlock,
		gen.SliceOf(genBlock),
	))

	properties.TestingRun(t)
}
