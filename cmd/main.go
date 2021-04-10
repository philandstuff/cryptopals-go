package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/philandstuff/cryptopals-go"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name: "cryptopals",
		Commands: []*cli.Command{
			set1(),
			set2(),
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
			{
				Name: "english-score",
				Action: func(c *cli.Context) error {
					buf, _ := ioutil.ReadAll(os.Stdin)
					score := cryptopals.Englishness(buf)
					fmt.Println(score)
					return nil
				},
			},
			{
				Name: "frequency-count",
				Action: func(c *cli.Context) error {
					var bytecount [256]byte
					var total int
					reader := bufio.NewReader(os.Stdin)
					for {
						c, err := reader.ReadByte()
						if err == io.EOF {
							break
						}
						bytecount[c]++
						total++
					}
					for _, b := range bytecount {
						fmt.Printf("%f,\n", float64(b)/float64(total))
					}
					return nil
				},
			},
			{
				Name:  "guess-keysize",
				Usage: "guess the keysize of a suspected vigenere ciphertext",
				Action: func(c *cli.Context) error {
					hex, _ := ioutil.ReadAll(os.Stdin)
					buf := cryptopals.HexDecode(string(hex))
					fmt.Println(cryptopals.GuessKeysize(buf))
					return nil
				},
			},
		},
	}
}
