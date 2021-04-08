package cryptopals

import (
	"bytes"
	"math"
)

var ENGLISH_FREQUENCY = [26]float64{
	0.08167, // a
	0.01492,
	0.02782,
	0.04253,
	0.1270, // e
	0.02228,
	0.02015,
	0.16094,
	0.16966, // i
	0.00153,
	0.00772,
	0.04025,
	0.02406,
	0.06749,
	0.07507, // o
	0.01929,
	0.00095,
	0.05987,
	0.06327,
	0.09056, // t
	0.02758,
	0.00978,
	0.02360,
	0.00150,
	0.01974,
	0.00074, // z
}

// with thanks to https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py
func Englishness(buf []byte) float64 {
	var total_per_letter [26]int
	// buf = bytes.ToLower(buf)
	for _, b := range buf {
		if b >= 'a' && b <= 'z' {
			total_per_letter[b-'a']++
		}
	}
	coeff := float64(0)
	for i := 0; i < 26; i++ {
		coeff += math.Sqrt(ENGLISH_FREQUENCY[i] * float64(total_per_letter[i]) / float64(len(buf)))
	}
	return coeff
}

// Finds the best-scoring single-byte XOR decrypt of buf.  Returns the
// decrypted bytes and the englishness-score.
func BestEnglishXorDecrypt(buf []byte) ([]byte, float64) {
	size := len(buf)
	var best_score float64
	var best_decrypt []byte
	for i := 0; i < 256; i++ {
		decrypt_try := XorBufs(buf, bytes.Repeat([]byte{byte(i)}, size))
		englishness := Englishness(decrypt_try)
		if englishness > best_score {
			best_score = englishness
			best_decrypt = decrypt_try
		}
	}
	return best_decrypt, best_score
}
