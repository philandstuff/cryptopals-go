package cryptopals_test

import (
	"bytes"
	"testing"

	"github.com/philandstuff/cryptopals-go"
)

// Challenge 1
func TestHexToBase64(t *testing.T) {
	decoded := cryptopals.HexDecode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	base64 := cryptopals.Base64Encode(decoded)
	if string(base64) != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("Actual %s did not match expected value", string(base64))
	}
}

// Challenge 2
func TestFixedXor(t *testing.T) {
	buf1 := cryptopals.HexDecode("1c0111001f010100061a024b53535009181c")
	buf2 := cryptopals.HexDecode("686974207468652062756c6c277320657965")
	xored := cryptopals.XorBufs(buf1, buf2)
	actual := cryptopals.HexEncode(xored)
	if actual != "746865206b696420646f6e277420706c6179" {
		t.Errorf("Actual %s did not match expected", actual)
	}
}

// Challenge 3
func TestDecryptFixedXor(t *testing.T) {
	buf := cryptopals.HexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	size := len(buf)
	var best_byte byte
	var best_match float64
	for i := 0; i < 256; i++ {
		decrypt_try := cryptopals.XorBufs(buf, bytes.Repeat([]byte{byte(i)}, size))
		englishness := cryptopals.Englishness(decrypt_try)
		if englishness > best_match {
			best_byte = byte(i)
			best_match = englishness
		}
	}
	decrypt := cryptopals.XorBufs(buf, bytes.Repeat([]byte{best_byte}, size))
	t.Log(string(decrypt))
	t.FailNow()
}
