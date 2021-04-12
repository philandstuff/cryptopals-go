package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/philandstuff/cryptopals-go"
	"github.com/urfave/cli/v2"
)

func challenge1(c *cli.Context) error {
	decoded := cryptopals.HexDecode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	base64 := cryptopals.Base64Encode(decoded)
	fmt.Println(string(base64))
	if string(base64) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		fmt.Println("Bingo!")
	}
	return nil
}

func challenge2(c *cli.Context) error {
	buf1 := cryptopals.HexDecode("1c0111001f010100061a024b53535009181c")
	buf2 := cryptopals.HexDecode("686974207468652062756c6c277320657965")
	xored := cryptopals.XorBufs(buf1, buf2)
	actual := cryptopals.HexEncode(xored)
	fmt.Println(actual)
	if actual == "746865206b696420646f6e277420706c6179" {
		fmt.Println("Bingo!")
	}
	return nil
}

func challenge3(c *cli.Context) error {
	text := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	buf := cryptopals.HexDecode(text)
	decrypt, _, _ := cryptopals.BestEnglishXorDecrypt(buf)
	fmt.Println(string(decrypt))
	return nil
}

func challenge4(c *cli.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	var best_score float64
	var best_decrypt []byte
	var best_key byte
	best_line := 1
	line := 1
	for scanner.Scan() {
		buf := cryptopals.HexDecode(scanner.Text())
		decrypt, key, score := cryptopals.BestEnglishXorDecrypt(buf)
		if score > best_score {
			best_key = key
			best_score = score
			best_decrypt = decrypt
			best_line = line
		}
		line++
	}
	fmt.Printf("%d, %d, %f: %s\n", best_line, best_key, best_score, string(best_decrypt))
	return nil
}

func challenge5(c *cli.Context) error {
	key := c.String("key")
	text, _ := ioutil.ReadAll(os.Stdin)
	xored := cryptopals.XorRepeating(text, []byte(key))
	actual := cryptopals.HexEncode(xored)
	fmt.Println(actual)
	if actual == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" || // hack for trailing newline, can't be bothered to sort it out
		actual == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f4f" {
		fmt.Println("Bingo!")
	}
	return nil
}

func challenge6(c *cli.Context) error {
	hex, _ := ioutil.ReadAll(os.Stdin)
	buf := cryptopals.HexDecode(string(hex))
	decrypt, key := cryptopals.BestEnglishRepeatingXorDecrypt(buf)

	fmt.Printf("Decrypt: %s\n", string(decrypt))
	fmt.Printf("Key: %x\n", key)
	return nil
}

func challenge7(c *cli.Context) error {
	key := []byte(c.String("key"))
	if len(key) != 16 {
		return fmt.Errorf("key %s was not exactly 16 bytes long", string(key))
	}
	input := base64.NewDecoder(base64.StdEncoding, os.Stdin)
	data, _ := ioutil.ReadAll(input)
	decrypted := make([]byte, len(data))
	cipher, _ := aes.NewCipher(key)
	decrypter := cryptopals.NewECBDecrypter(cipher)
	decrypter.CryptBlocks(decrypted, data)
	fmt.Println(string(decrypted))
	return nil
}

func challenge8(c *cli.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	line := 1
	for scanner.Scan() {
		buf := cryptopals.HexDecode(scanner.Text())
		if block := cryptopals.DetectRepeatedBlock(buf); block != nil {
			fmt.Printf("line %d, block %x\n", line, block)
		}
		line++
	}
	return nil
}

func set1() *cli.Command {
	return &cli.Command{
		Name: "set1",
		Subcommands: []*cli.Command{
			{
				Name:   "challenge1",
				Usage:  "convert hex to base64",
				Action: challenge1,
			},
			{
				Name:   "challenge2",
				Usage:  "fixed xor",
				Action: challenge2,
			},
			{
				Name:   "challenge3",
				Usage:  "decrypt single-byte xor",
				Action: challenge3,
			},
			{
				Name:   "challenge4",
				Usage:  "find an english single-byte xor from many, provided on stdin",
				Action: challenge4,
			},
			{
				Name:  "challenge5",
				Usage: "repeating-key XOR",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "key",
						Value: "ICE",
						Usage: "Key to use for XOR",
					},
				},
				Action: challenge5,
			},
			{
				Name:   "challenge6",
				Usage:  "break repeating-key XOR",
				Action: challenge6,
			},
			{
				Name:  "challenge7",
				Usage: "AES ECB",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "key",
						Value: "YELLOW SUBMARINE",
						Usage: "AES key (exactly 16 bytes)",
					},
				},
				Action: challenge7,
			},
			{
				Name:   "challenge8",
				Usage:  "detect ECB",
				Action: challenge8,
			},
		},
	}
}
