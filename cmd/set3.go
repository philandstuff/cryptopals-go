package main

import (
	"fmt"

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

func set3() *cli.Command {
	return &cli.Command{
		Name: "set3",
		Subcommands: []*cli.Command{
			{
				Name:   "challenge17",
				Usage:  "padding oracle",
				Action: challenge17,
			},
		},
	}
}
