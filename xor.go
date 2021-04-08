package cryptopals

// assumes len(buf1) <= len(buf2)
func XorBufs(buf1, buf2 []byte) []byte {
	out := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i += 1 {
		out[i] = buf1[i] ^ buf2[i]
	}
	return out
}
