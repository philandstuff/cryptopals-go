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

	y := Temper(mt.state[mt.index])
	mt.index++
	return y
}

func Temper(x uint32) uint32 {
	y := x
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	return y
}

// untemper working. First, the right shift operation:
// 1010011011 x
// 0010100110 x >> 2

// 1000111101 x ^ x >> 2 (== z)
// 0010001111 z >> 2
// 0000100011 z >> 4
// 0000001000 z >> 6
// 0000000010 z >> 8
// 1010011011 XOR all the above
//
// solve for x: x ^ (x >> 2) = z
// for bit i:
// x_i ^ x_{i+2} == z_i
// for top 2 bits:
// x_i = z_i
// for next 2 bits:
// x_i = z_{i+2} ^ z_i
// for next 2 bits:
// x_i = z_{i+4} ^ z_{i+2} ^ z_i

// now, the left-shift and mask operation:
//
// solve for x: x ^ ((x << 2) & c) = z
// for bit i:
// x_i ^ (x_{i-2} & c_i) = z_i
// for lowest 2 bits:
// x_i = z_i
// for general bits:
// x_i = z_i ^ (x_{i-2} & c_i)
// expanding x_{i-2}:
// x_i = z_i ^ ((z_{i-2} ^ (x_{i-4} & c_{i-2})) & c_i)
// this terminates if we ever get a c_i == 0
// x = z ^ ((x << 2) & c)
// x = z ^ (((z ^ ((x << 2) & c)) << 2) & c)
// x = z ^ ((z << 2 ^ ((x << 4) & c << 2)) & c)
//
// 1010011011 x
// 1001101100 x << 2
// 0111110100 c
// 0001100100 (x << 2) & c

// 1011111111 x ^ ((x << 2) & c) (== z)

// 1011111100 z << 2
// 0011110100 (z << 2) & c
// 1111110000 z << 4
// 1111000000 z << 6
// 1100000000 z << 8
// 0000000000 z << 10
// 1010011011 XOR all the above
// 0110110100 c
// 0010010000 & the above two rows
// 1010111111 z
// 1000101111 XOR the above two rows

func Untemper(x uint32) uint32 {
	x = x ^ x>>l // 2*l > w so one term is enough

	x = x ^ ((x << t) & c) // c << t == 0 so one term is enough

	x = x ^ (((x ^ (((x ^ (((x ^ ((x << s) & b)) << s) & b)) << s) & b)) << s) & b)

	x = x ^ x>>u ^ x>>(2*u) // 3*u > w
	return x
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
