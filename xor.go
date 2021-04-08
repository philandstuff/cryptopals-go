package cryptopals

import "bytes"

// assumes buf1 and buf2 are the same length
func XorBufs(buf1, buf2 []byte) []byte {
	out := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i += 1 {
		out[i] = buf1[i] ^ buf2[i]
	}
	return out
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
