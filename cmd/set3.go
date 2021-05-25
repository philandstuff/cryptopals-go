package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

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
	// seed := c.Uint("seed")
	mt := MT.NewMTFromSlice([]uint32{0x123, 0x234, 0x345, 0x456})
	for i := 0; i < 200; i++ {
		fmt.Printf("%10d %10d %10d %10d %10d \n", mt.Next(), mt.Next(), mt.Next(), mt.Next(), mt.Next())
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
		},
	}
}
