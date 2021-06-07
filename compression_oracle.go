package cryptopals

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"log"
	"math/rand"
)

type CompressionOracle struct {
	blockCipher cipher.Block
}

// taken from challenge 17
var compressionOracleCipherText = "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="

func NewCompressionOracle() *CompressionOracle {
	var key [16]byte
	rand.Read(key[:])
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return &CompressionOracle{blockCipher: cipher}
}

func (co *CompressionOracle) GetEncryptedCookie(userInput []byte) []byte {
	secretText, err := base64.StdEncoding.DecodeString(compressionOracleCipherText)
	if err != nil {
		panic("can't happen")
	}

	var outbuf bytes.Buffer
	gzout, _ := gzip.NewWriterLevel(&outbuf, gzip.BestCompression)
	n, err := gzout.Write(secretText)
	if err != nil {
		panic(err)
	}
	log.Printf("wrote %d", n)
	n, err = gzout.Write(userInput)
	if err != nil {
		panic(err)
	}
	log.Printf("wrote %d", n)
	gzout.Close()

	buf := outbuf.Bytes()

	log.Printf("initial len %d", len(buf))
	nonce := rand.Uint64()
	enc := NewCTR(co.blockCipher, nonce)
	enc.XORKeyStream(buf, buf)

	return buf
	// we need to prepend nonceBytes for a theoretical consumer, even though they end up not being used at all
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, nonce)
	return append(nonceBytes, buf...)
}

// attack code

func CompressionOracleAttack(oracle *CompressionOracle) string {
	knownText := []byte{}
	buf := oracle.GetEncryptedCookie(knownText)
	log.Printf("bytes nil, length %d", len(buf))
	for i := 0; i < 10; i++ {
		guess := make([]byte, i)
		for j := 0; j < i; j++ {
			guess[j] = byte(j)
		}
		buf := oracle.GetEncryptedCookie(guess)
		log.Printf("bytes %x, length %d", guess, len(buf))
	}
	return string(knownText)
}
