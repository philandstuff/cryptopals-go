package cryptopals

import "errors"

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

// errors if padding is invalid
func TrimPkcs7Padding(buf []byte) ([]byte, error) {
	bytesToTrim := buf[len(buf)-1]
	if bytesToTrim == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := 1; i <= int(bytesToTrim); i++ {
		if buf[len(buf)-i] != bytesToTrim {
			return nil, errors.New("invalid padding")
		}
	}
	return buf[:len(buf)-int(bytesToTrim)], nil
}
