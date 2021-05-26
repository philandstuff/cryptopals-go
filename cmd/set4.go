package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/philandstuff/cryptopals-go"
	"github.com/urfave/cli/v2"
)

func challenge27(c *cli.Context) error {
	c27 := cryptopals.NewC27Thing()
	cipherText := c27.EncryptWithUserData("lalalala")
	for i := 0; i < 16; i++ {
		cipherText[i+16] = 0             // set block 2 to 0
		cipherText[i+32] = cipherText[i] // set block 3 equal to block 1
	}
	_, err := c27.DecryptAndCheckForAdmin(cipherText)
	if err != nil {
		hx := strings.Split(err.Error(), " ")[1]
		bytes, err := hex.DecodeString(hx)
		if err != nil {
			return err
		}
		block1 := bytes[0:16]
		block3 := bytes[32:48]
		cryptopals.XorBufs(block1, block3)

		cipher, err := aes.NewCipher(block1)
		if err != nil {
			panic(err)
		}
		dec := cryptopals.NewCBCDecrypter(cipher, block1)
		cipherText := c27.EncryptWithUserData("lalalala")
		plainText := make([]byte, len(cipherText))
		dec.CryptBlocks(plainText, cipherText)
		fmt.Printf("Stole key, decrypted: %s\n", plainText)
	}

	return nil
}
func set4() *cli.Command {
	return &cli.Command{
		Name: "set4",
		Subcommands: []*cli.Command{
			{
				Name:   "challenge25",
				Usage:  "random-access read-write AES CTR",
				Action: unimplemented,
			},
			{
				Name:   "challenge26",
				Usage:  "CTR bitflipping",
				Action: unimplemented,
			},
			{
				Name:   "challenge27",
				Usage:  "CBC with key == IV",
				Action: challenge27,
			},
		},
	}
}
