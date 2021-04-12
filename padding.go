package cryptopals

// Pkcs7pad pads buf with PKCS#7 padding to the given block size.  buf
// will be append()ed to to make this happen, so treat it like
// append().
func Pkcs7pad(buf []byte, blockSize int) []byte {
	if blockSize >= 256 {
		panic("block size too big")
	}
	lastBlockBytes := len(buf) % blockSize
	paddingBytes := blockSize - lastBlockBytes

	for i := 0; i < paddingBytes; i++ {
		buf = append(buf, byte(paddingBytes))
	}
	return buf
}
