// package mt implements the MT19937 Mersenne Twister RNG
package mt

const w = 32
const n = 624
const m = 397
const r = 31

const a = 0x9908B0DF
const u = 11
const d = 0xffffffff
const s = 7
const b = 0x9D2C5680
const t = 15
const c = 0xEFC60000
const l = 18

const lower_mask uint32 = (1 << r) - 1
const upper_mask uint32 = ^lower_mask

const f = 1812433253

type MT struct {
	state [n]uint32
	index uint32
}

func NewMTFromSeed(seed uint32) *MT {
	mt := MT{}
	mt.index = n
	mt.state[0] = seed
	for i := uint32(1); i < n; i++ {
		mt.state[i] = f*(mt.state[i-1]^(mt.state[i-1]>>(w-2))) + i
	}
	return &mt
}

// NewMTFromSlice is a port of init_by_array in the original mersenne
// twister code
func NewMTFromSlice(initKey []uint32) *MT {
	mt := NewMTFromSeed(19650218)
	i := uint32(1)
	j := uint32(0)
	k := uint32(len(initKey))
	if n > k {
		k = n
	}
	for ; k != 0; k-- {
		mt.state[i] = (mt.state[i] ^ ((mt.state[i-1] ^ (mt.state[i-1] >> 30)) * 1664525)) + initKey[j] + j // non linear, apparently
		i++
		j++
		if i >= n {
			mt.state[0] = mt.state[n-1]
			i = 1
		}
		if j >= uint32(len(initKey)) {
			j = 0
		}
	}
	for k = n - 1; k != 0; k-- {
		mt.state[i] = (mt.state[i] ^ ((mt.state[i-1] ^ (mt.state[i-1] >> 30)) * 1566083941)) - i // non linear, again apparently
		i++
		if i >= n {
			mt.state[0] = mt.state[n-1]
			i = 1
		}
	}
	mt.state[0] = 0x80000000 // MSB is 1 assuring non-zero initial array
	return mt
}

func (mt *MT) Next() uint32 {
	if mt.index > n {
		panic("can't happen")
	}
	if mt.index == n {
		mt.twist()
	}

	y := mt.state[mt.index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)

	mt.index++
	return y
}

// generate the next n values of x_i
func (mt *MT) twist() {
	for i := 0; i < n; i++ {
		x := (mt.state[i] & upper_mask) + (mt.state[(i+1)%n] & lower_mask)
		xA := x >> 1
		if x%2 == 1 {
			xA = xA ^ a
		}
		mt.state[i] = mt.state[(i+m)%n] ^ xA
	}
	mt.index = 0
}
