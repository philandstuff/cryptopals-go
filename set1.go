package cryptopals

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

func hexByteToNybble(in byte) int {
	if in <= '9' {
		return int(in - '0')
	}
	return int(in - 'a' + 10)
}

func HexToBase64(in []byte) []byte {
	out := []byte{}
	tmp := 0
	bits := 0
	for _, nybble := range in {
		tmp = tmp<<4 | hexByteToNybble(nybble)
		bits += 4
		if bits >= 6 {
			bits = bits - 6
			out = append(out, bitsToBase64Char(byte((tmp>>bits)&0x3f)))
		}
	}
	return out
}
