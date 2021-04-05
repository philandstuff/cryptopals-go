package cryptopals_test

import (
	"testing"

	"github.com/philandstuff/cryptopals-go"
)

func TestHexToBase64(t *testing.T) {
	decoded := cryptopals.HexDecode([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	base64 := cryptopals.Base64Encode(decoded)
	if string(base64) != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("Actual %s did not match expected value", string(base64))
	}
}
