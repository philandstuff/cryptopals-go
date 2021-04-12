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

func TestECBDecryptEncrypt(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("ECB encrypt/decrypt is a no-op", prop.ForAll(
		func(key []byte, data []byte) bool {
			// trim to a block boundary
			cipher, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			data = data[:(len(data)/cipher.BlockSize())*cipher.BlockSize()]
			encrypter := cryptopals.NewECBEncrypter(cipher)
			decrypter := cryptopals.NewECBDecrypter(cipher)
			actual := make([]byte, len(data))
			encrypter.CryptBlocks(actual, data)
			decrypter.CryptBlocks(actual, actual)
			return bytes.Equal(actual, data)
		},
		gen.SliceOfN(16, gen.UInt8()),
		gen.SliceOf(gen.UInt8()),
	))
	properties.TestingRun(t)
}
