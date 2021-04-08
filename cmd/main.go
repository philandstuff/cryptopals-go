package main

import (
	"fmt"
	"os"

	"github.com/philandstuff/cryptopals-go"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name: "cryptopals",
		Commands: []*cli.Command{
			set1(),
			helpers(),
		},
	}

	app.Run(os.Args)
}

func helpers() *cli.Command {
	return &cli.Command{
		Name: "helpers",
		Subcommands: []*cli.Command{
			{
				Name:      "hexdecode",
				ArgsUsage: "[hex-to-decode]",
				Action: func(c *cli.Context) error {
					buf := cryptopals.HexDecode(c.Args().Get(0))
					for i, byte := range buf {
						// sanitise unprintable characters
						// yeah, UTF-8, whatever
						if byte < 0x20 || byte >= 0x7f {
							buf[i] = '.'
						}
					}
					fmt.Println(string(buf))
					return nil
				},
			},
		},
	}
}
