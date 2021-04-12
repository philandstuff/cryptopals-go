package cryptopals

import (
	"crypto/cipher"
	"encoding/binary"
)

//// Electronic Code Book (ECB)

type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(&ecb{
		b:         b,
		blockSize: b.BlockSize(),
	})
}

func (e *ecbEncrypter) BlockSize() int { return e.blockSize }

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("Not a fixed number of blocks")
	}
	if len(dst) < len(src) {
		panic("Not enough room in dst")
	}
	for i := 0; i < len(src)/e.blockSize; i++ {
		e.b.Encrypt(dst[i*e.blockSize:], src[i*e.blockSize:])
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(&ecb{
		b:         b,
		blockSize: b.BlockSize(),
	})
}

func (d *ecbDecrypter) BlockSize() int { return d.blockSize }

func (d *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%d.blockSize != 0 {
		panic("Not a fixed number of blocks")
	}
	if len(dst) < len(src) {
		panic("Not enough room in dst")
	}
	for i := 0; i < len(src)/d.blockSize; i++ {
		d.b.Decrypt(dst[i*d.blockSize:], src[i*d.blockSize:])
	}
}

//// Cipher Block Chaining (CBC)

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

type cbcEncrypter cbc

func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("invalid IV")
	}
	return (*cbcEncrypter)(&cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	})
}

func (e *cbcEncrypter) BlockSize() int { return e.blockSize }

func (e *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("Not a fixed number of blocks")
	}
	if len(dst) < len(src) {
		panic("Not enough room in dst")
	}
	next := make([]byte, len(e.iv))
	copy(next, e.iv)
	for i := 0; i < len(src)/e.blockSize; i++ {
		XorBufs(next, src[i*e.blockSize:(i+1)*e.blockSize])
		e.b.Encrypt(next, next)
		copy(dst[i*e.blockSize:], next)
	}
}

type cbcDecrypter cbc

func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("invalid IV")
	}
	return (*cbcDecrypter)(&cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	})
}

func (d *cbcDecrypter) BlockSize() int { return d.blockSize }

func (d *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%d.blockSize != 0 {
		panic("Not a fixed number of blocks")
	}
	if len(dst) < len(src) {
		panic("Not enough room in dst")
	}
	next := make([]byte, d.blockSize)
	copy(next, d.iv)
	srcBlock := make([]byte, d.blockSize)
	for i := 0; i < len(src)/d.blockSize; i++ {
		// we copy srcBlock just in case dst and src are the same
		// slice
		copy(srcBlock, src[i*d.blockSize:(i+1)*d.blockSize])
		d.b.Decrypt(dst[i*d.blockSize:], srcBlock)
		XorBufs(dst[i*d.blockSize:(i+1)*d.blockSize], next)
		copy(next, srcBlock)
	}
}

// Useful for spotting ECB in the wild

func DetectRepeatedBlock(data []byte) []byte {
	seen := make(map[uint64]map[uint64]bool)
	for len(data) >= 16 {
		i1 := binary.BigEndian.Uint64(data)
		i2 := binary.BigEndian.Uint64(data[8:])
		m, ok := seen[i1]
		if !ok {
			seen[i1] = make(map[uint64]bool)
			m = seen[i1]
		}
		if m[i2] {
			return data[0:16]
		}
		m[i2] = true

		data = data[16:]
	}
	return nil
}
