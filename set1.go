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

func hexByteToNybble(in byte) byte {
	if in <= '9' {
		return in - '0'
	}
	return in - 'a' + 10
}

func HexDecode(in []byte) []byte {
	out := make([]byte, len(in)/2)
	for i := 0; i < len(in); i += 2 {
		highNybble := hexByteToNybble(in[i])
		lowNybble := hexByteToNybble(in[i+1])
		out[i/2] = highNybble<<4 | lowNybble
	}
	return out
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
