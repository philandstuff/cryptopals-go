package cryptopals_test

import (
	"bytes"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/maxatome/go-testdeep/td"
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

// Challenge 13

func TestParseKV(t *testing.T) {
	t.Run("one key/value pair", func(t *testing.T) {
		in := "foo=bar"
		out := cryptopals.ParseKV(in)
		expected := map[string]string{"foo": "bar"}
		td.Cmp(t, out, expected)
	})
	t.Run("two key/value pairs", func(t *testing.T) {
		in := "foo=bar&baz=quux"
		out := cryptopals.ParseKV(in)
		expected := map[string]string{"foo": "bar", "baz": "quux"}
		td.Cmp(t, out, expected)
	})
}

func TestProfileFor(t *testing.T) {
	t.Run("basic usage", func(t *testing.T) {
		in := "foo@example.com"
		out := cryptopals.ProfileFor(in)
		expected := "email=foo@example.com&uid=10&role=user"
		td.Cmp(t, out, expected)
	})
	t.Run("nasty characters should get eaten", func(t *testing.T) {
		in := "foo@example.com&role=admin"
		out := cryptopals.ProfileFor(in)
		expected := "email=foo@example.com&uid=10&role=user"
		td.Cmp(t, out, expected)
	})
}

func TestTrimPkcs7Padding(t *testing.T) {
	t.Run("0x1", func(t *testing.T) {
		in := []byte{1, 2, 3, 1}
		out := cryptopals.TrimPkcs7Padding(in)
		expected := []byte{1, 2, 3}
		td.Cmp(t, out, expected)
	})
	t.Run("0x2", func(t *testing.T) {
		in := []byte{1, 2, 2, 2}
		out := cryptopals.TrimPkcs7Padding(in)
		expected := []byte{1, 2}
		td.Cmp(t, out, expected)
	})
}
