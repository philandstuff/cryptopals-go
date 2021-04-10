package cryptopals

func Pkcs7pad(buf []byte, size int) []byte {
	if size >= 256 {
		panic("block size too big")
	}
	outsize := ((len(buf) / size) + 1) * size
	out := make([]byte, outsize)
	copy(out, buf)
	paddingBytes := outsize - len(buf)
	if paddingBytes <= 0 || paddingBytes > size {
		panic("logic error")
	}
	for i := len(buf); i < outsize; i++ {
		out[i] = byte(paddingBytes)
	}
	return out
}
