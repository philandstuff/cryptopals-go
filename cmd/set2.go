package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"time"

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

func challenge10(c *cli.Context) error {
	key := []byte(c.String("key"))
	if len(key) != 16 {
		return fmt.Errorf("key %s was not exactly 16 bytes long", string(key))
	}
	iv := []byte(c.String("iv"))
	if len(iv) != 16 {
		return fmt.Errorf("iv %x was not exactly 16 bytes long", iv)
	}
	input := base64.NewDecoder(base64.StdEncoding, os.Stdin)
	data, _ := ioutil.ReadAll(input)
	decrypted := make([]byte, len(data))
	cipher, _ := aes.NewCipher(key)
	decrypter := cryptopals.NewCBCDecrypter(cipher, iv)
	decrypter.CryptBlocks(decrypted, data)
	fmt.Println(string(decrypted))
	return nil
}

func challenge11(c *cli.Context) error {
	rand.Seed(time.Now().UnixNano())
	isECBMode := cryptopals.Challenge11DetectECB(cryptopals.Challenge11EncryptRandomData)
	if isECBMode {
		log.Print("Detected ECB")
	} else {
		log.Print("Detected not-ECB")
	}
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
			{
				Name:  "challenge10",
				Usage: "CBC decryption",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "key",
						Value: "YELLOW SUBMARINE",
						Usage: "key",
					},
					&cli.StringFlag{
						Name: "iv",
						Value: string([]byte{
							0, 0, 0, 0, 0, 0, 0, 0,
							0, 0, 0, 0, 0, 0, 0, 0}),
						Usage: "initialization vector",
					},
				},
				Action: challenge10,
			},
			{
				Name:   "challenge11",
				Usage:  "ECB/CBC detection",
				Action: challenge11,
			},
		},
	}
}
