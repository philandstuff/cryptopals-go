package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/philandstuff/cryptopals-go"
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
		},
	}
}
