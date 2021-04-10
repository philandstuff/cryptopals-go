package cryptopals

import (
	"bytes"
	"math"
	"math/bits"
)

func XorBufs(buf1, buf2 []byte) []byte {
	if len(buf1) > len(buf2) {
		panic("buf1 not long enough")
	}
	out := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i += 1 {
		out[i] = buf1[i] ^ buf2[i]
	}
	return out
}

func XorRepeating(buf, key []byte) []byte {
	keystream := bytes.Repeat([]byte(key), (len(buf)/len(key))+1)
	xored := XorBufs(buf, keystream)
	return xored
}

func HammingDistance(buf1, buf2 []byte) int {
	xored := XorBufs(buf1, buf2)
	count := 0
	for _, b := range xored {
		count += bits.OnesCount8(b)
	}
	return count
}

func GuessKeysize(buf []byte) int {
	var best_dist float64 = math.Inf(1)
	var best_keysize int
	for i := 2; i < 40; i++ {
		if i*4 > len(buf) {
			break
		}
		dist1 := HammingDistance(buf[i*0:i*1], buf[i*1:i*2])
		dist2 := HammingDistance(buf[i*1:i*2], buf[i*2:i*3])
		dist3 := HammingDistance(buf[i*2:i*3], buf[i*3:i*4])
		dist := float64(dist1+dist2+dist3) / float64(i)
		if dist < best_dist {
			best_dist = dist
			best_keysize = i
		}
	}
	return best_keysize
}
