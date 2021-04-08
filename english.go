package cryptopals

import (
	"bytes"
	"math"
)

var ENGLISH_FREQUENCY = map[byte]float64{
	'a': 0.08167,
	'b': 0.01492,
	'c': 0.02782,
	'd': 0.04253,
	'e': 0.1270,
	'f': 0.02228,
	'g': 0.02015,
	'h': 0.06094,
	'i': 0.06966,
	'j': 0.00153,
	'k': 0.00772,
	'l': 0.04025,
	'm': 0.02406,
	'n': 0.06749,
	'o': 0.07507,
	'p': 0.01929,
	'q': 0.00095,
	'r': 0.05987,
	's': 0.06327,
	't': 0.09056,
	'u': 0.02758,
	'v': 0.00978,
	'w': 0.02360,
	'x': 0.00150,
	'y': 0.01974,
	'z': 0.00074,
}

// with thanks to https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py
func Englishness(buf []byte) float64 {
	var total_per_letter [26]int
	for _, b := range buf {
		if b >= 'a' && b <= 'z' {
			total_per_letter[b-'a']++
		}
		// if b >= 'A' && b <= 'Z' {
		// 	total_per_letter[b-'A']++
		// }
	}
	coeff := float64(0)
	for i := 0; i < 26; i++ {
		coeff += math.Sqrt(ENGLISH_FREQUENCY[byte(i+'a')] * float64(total_per_letter[i]) / float64(len(buf)))
	}
	return coeff
}

// Finds the best-scoring single-byte XOR decrypt of buf.  Returns the
// decrypted bytes, the key byte and the englishness-score.
func BestEnglishXorDecrypt(buf []byte) ([]byte, byte, float64) {
	size := len(buf)
	var best_score float64
	var best_decrypt []byte
	var best_key byte
	for i := 0; i < 256; i++ {
		decrypt_try := XorBufs(buf, bytes.Repeat([]byte{byte(i)}, size))
		englishness := Englishness(decrypt_try)
		if englishness > best_score {
			best_score = englishness
			best_decrypt = decrypt_try
			best_key = byte(i)
		}
	}
	return best_decrypt, best_key, best_score
}

// Finds the best-scoring repeating XOR decrypt of buf.  Returns the
// decrypted bytes and the key.
func BestEnglishRepeatingXorDecrypt(buf []byte) ([]byte, []byte) {
	keysize := GuessKeysize(buf)
	keysizeChunks := make([][]byte, (len(buf)/keysize)+1)
	for i := range keysizeChunks {
		keysizeChunks[i] = buf[i*keysize : (i+1)*keysize]
	}
	transposeChunks := Transpose(keysizeChunks)
	guessedKey := make([]byte, keysize)
	for i := range transposeChunks {
		_, key, _ := BestEnglishXorDecrypt(transposeChunks[i])
		guessedKey[i] = key
	}
	decrypt := XorRepeating(buf, guessedKey)
	return decrypt, guessedKey
}
