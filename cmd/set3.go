package main

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"

	"github.com/philandstuff/cryptopals-go"
	MT "github.com/philandstuff/cryptopals-go/mt"
	"github.com/urfave/cli/v2"
)

func challenge17(c *cli.Context) error {
	c17 := cryptopals.NewC17Thing()
	cipherText := c17.GetEncryptedCookie()
	if c17.IsValidPadding(cipherText) {
		fmt.Println("valid")
	} else {
		fmt.Println("invalid")
	}
	decrypt := cryptopals.C17PaddingOracleAttack(cipherText, c17)
	fmt.Printf("Decrypted: %#v\n", decrypt)
	return nil
}

func challenge17a(c *cli.Context) error {
	c17 := cryptopals.NewCompressionOracle()
	cryptopals.CompressionOracleAttack(c17)
	return nil
}

func challenge18(c *cli.Context) error {
	key := []byte(c.String("key"))
	if len(key) != 16 {
		return fmt.Errorf("key %s was not exactly 16 bytes long", string(key))
	}
	nonce := c.Uint64("nonce")
	input := base64.NewDecoder(base64.StdEncoding, os.Stdin)
	data, _ := ioutil.ReadAll(input)
	decrypted := make([]byte, len(data))
	cipher, _ := aes.NewCipher(key)
	decrypter := cryptopals.NewCTR(cipher, nonce)
	decrypter.XORKeyStream(decrypted, data)
	fmt.Println(string(decrypted))
	return nil
}

func challenge19(c *cli.Context) error {
	cipherTexts := cryptopals.Challenge19CipherTexts()

	guessIndex := c.Int("guess-index")
	optGuessPlaintext := c.String("guess-plaintext")
	guessedCipherText := cipherTexts[guessIndex]
	keyStream := []byte(optGuessPlaintext)
	cryptopals.XorBufs(keyStream, guessedCipherText[:len(keyStream)])

	for i, cipherText := range cipherTexts {
		if len(cipherText) < len(keyStream) {
			cryptopals.XorBufs(cipherText, keyStream[:len(cipherText)])
		} else {
			cryptopals.XorBufs(cipherText, keyStream)
			cipherText = cipherText[:len(keyStream)]
		}
		fmt.Printf("%d: %#v\n", i, string(cipherText))
	}
	return nil
}

func challenge20(c *cli.Context) error {
	cipherTexts := cryptopals.Challenge19CipherTexts()

	minlength := 1000
	for _, cipherText := range cipherTexts {
		if minlength > len(cipherText) {
			minlength = len(cipherText)
		}
	}
	repeatingCipherText := []byte{}
	for _, cipherText := range cipherTexts {
		repeatingCipherText = append(repeatingCipherText, cipherText[:minlength]...)
	}
	_, keystream := cryptopals.BestEnglishRepeatingXorDecrypt(repeatingCipherText)

	for _, cipherText := range cipherTexts {
		cryptopals.XorBufs(cipherText, keystream)
		fmt.Println(string(cipherText[:minlength]))
	}
	return nil
}

func challenge21(c *cli.Context) error {
	mt := MT.NewMTFromSlice([]uint32{0x123, 0x234, 0x345, 0x456})
	for i := 0; i < 200; i++ {
		fmt.Printf("%10d %10d %10d %10d %10d \n", mt.Next(), mt.Next(), mt.Next(), mt.Next(), mt.Next())
	}
	return nil
}

func challenge22(c *cli.Context) error {
	var value uint32
	{
		// initialise RNG at some point in the last 1000 seconds
		offset := rand.Intn(1000) + 40
		seed := time.Now().Unix() - int64(offset)
		mt := MT.NewMTFromSeed(uint32(seed))
		value = mt.Next()
	}

	// try to crack the seed, without the original mt in scope, just
	// based on value
	now := time.Now().Unix()
	for i := 0; i < 2000; i++ {
		seedGuess := uint32(now) - uint32(i)
		mt := MT.NewMTFromSeed(seedGuess)
		if mt.Next() == value {
			fmt.Printf("Found seed %d, hooray!\n", seedGuess)
			return nil
		}
	}
	return errors.New("Couldn't find seed")
}

func challenge23(c *cli.Context) error {
	seed := rand.Uint32()
	gen := MT.NewMTFromSeed(seed)
	gen2 := MT.NewMTFromSeed(seed)
	cloned := MT.DuplicateMT(gen2)
	fmt.Println("cloned a generator, here are 20 test outputs:")
	for i := 0; i < 20; i++ {
		fmt.Printf("%10d %10d\n", gen.Next(), cloned.Next())
	}
	if *gen == *cloned {
		fmt.Println("They are equal as structs, so have equal state")
	} else {
		fmt.Println("They are not equal as structs")
	}
	return nil
}

func set3() *cli.Command {
	return &cli.Command{
		Name: "set3",
		Subcommands: []*cli.Command{
			{
				Name:   "challenge17",
				Usage:  "padding oracle",
				Action: challenge17,
			},
			{
				Name:   "challenge17a",
				Usage:  "compression oracle",
				Action: challenge17a,
			},
			{
				Name:  "challenge18",
				Usage: "CTR mode",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "key",
						Value: "YELLOW SUBMARINE",
						Usage: "key",
					},
					&cli.Uint64Flag{
						Name:  "",
						Value: uint64(0),
						Usage: "nonce",
					},
				},
				Action: challenge18,
			},
			{
				Name:  "challenge19",
				Usage: "Fixed-nonce CTR, broken manually",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "guess-plaintext",
						Value: "",
					},
					&cli.IntFlag{
						Name:  "guess-index",
						Value: 0,
					},
				},
				Action: challenge19,
			},
			{
				Name:   "challenge20",
				Usage:  "Fixed-nonce CTR, broken statistically",
				Action: challenge20,
			},
			{
				Name:   "challenge21",
				Usage:  "MT19937 RNG",
				Action: challenge21,
			},
			{
				Name:   "challenge22",
				Usage:  "Crack a MT19937 RNG seed",
				Action: challenge22,
			},
			{
				Name:   "challenge23",
				Usage:  "Clone a MT19937 RNG from outside",
				Action: challenge23,
			},
			{
				Name:   "challenge24",
				Usage:  "Break the MT19937 stream cipher",
				Action: unimplemented,
			},
		},
	}
}
