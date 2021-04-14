package cryptopals_test

import (
	"bytes"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/philandstuff/cryptopals-go"
)

// Challenge 9
func TestPkcs7Padding(t *testing.T) {
	t.Run("0x01", func(t *testing.T) {
		in := []byte{1, 2, 3}
		out := cryptopals.Pkcs7pad(in, 4)
		expected := []byte{1, 2, 3, 1}
		if !bytes.Equal(out, expected) {
			t.Errorf("Expected %x to be %x", out, expected)
		}
	})
	t.Run("0x02", func(t *testing.T) {
		in := []byte{1, 2}
		out := cryptopals.Pkcs7pad(in, 4)
		expected := []byte{1, 2, 2, 2}
		if !bytes.Equal(out, expected) {
			t.Errorf("Expected %x to be %x", out, expected)
		}
	})
	t.Run("complete block", func(t *testing.T) {
		in := []byte{1, 2, 3, 4}
		out := cryptopals.Pkcs7pad(in, 4)
		expected := []byte{1, 2, 3, 4, 4, 4, 4, 4}
		if !bytes.Equal(out, expected) {
			t.Errorf("Expected %x to be %x", out, expected)
		}
	})
}

func TestECBDetector(t *testing.T) {
	properties := gopter.NewProperties(nil)

	properties.Property("DetectECB reliably detects ECB mode from an oracle", prop.ForAll(
		func(chooseECB bool, key, iv []byte, prefix, suffix []byte) bool {
			encryptionOracle := cryptopals.Challenge11EncryptData(chooseECB, key, iv, prefix, suffix)
			detectedECB := cryptopals.Challenge11DetectECB(encryptionOracle)
			return chooseECB == detectedECB
		},
		gen.Bool(),
		genBlock, genBlock,
		gen.SliceOf(gen.UInt8()),
		gen.SliceOf(gen.UInt8()),
	))

	properties.TestingRun(t)
}
