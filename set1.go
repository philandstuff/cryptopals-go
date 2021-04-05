package cryptopals

import "fmt"

// in: a value in 6-bit range
// out: the base64 representation of this value
func bitsToBase64Char(n byte) byte {
	if n <= 25 {
		return n + 'A'
	}
	if n <= 51 {
		return n - 26 + 'a'
	}
	if n <= 61 {
		return n - 52 + '0'
	}
	if n == 62 {
		return '+'
	}
	if n == 63 {
		return '/'
	}
	panic("out of range")
}

func HexDecode(in string) []byte {
	var out []byte
	fmt.Sscanf(in, "%x", &out)
	return out
}

func HexEncode(in []byte) string {
	return fmt.Sprintf("%x", in)
}

func Base64Encode(in []byte) []byte {
	out := []byte{}
	tmp := 0
	bits := 0
	for _, b := range in {
		tmp = tmp<<8 | int(b)
		bits += 8
		for bits >= 6 {
			bits = bits - 6
			out = append(out, bitsToBase64Char(byte((tmp>>bits)&0x3f)))
		}
	}
	// FIXME tmp might have 2 or 4 spare bits left to output
	return out
}

// Challenge 2

// assumes buf1 and buf2 are the same length
func XorBufs(buf1, buf2 []byte) []byte {
	out := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i += 1 {
		out[i] = buf1[i] ^ buf2[i]
	}
	return out
}
