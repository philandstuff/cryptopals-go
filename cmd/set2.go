package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/philandstuff/cryptopals-go"
	"github.com/urfave/cli/v2"
)

func challenge9(c *cli.Context) error {
	size := c.Int("size")
	in, _ := ioutil.ReadAll(os.Stdin)
	out := cryptopals.Pkcs7pad(in, size)
	fmt.Printf("%q\n", string(out))
	return nil
}

func set2() *cli.Command {
	return &cli.Command{
		Name: "set2",
		Subcommands: []*cli.Command{
			{
				Name:  "challenge9",
				Usage: "pkcs#7 padding",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "size",
						Value: 20,
						Usage: "Block size to pad to",
					},
				},
				Action: challenge9,
			},
		},
	}
}
