package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
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
	isECBMode := cryptopals.Challenge11DetectECB(cryptopals.Challenge11EncryptRandomData)
	if isECBMode {
		log.Print("Detected ECB")
	} else {
		log.Print("Detected not-ECB")
	}
	return nil
}

func challenge12(c *cli.Context) error {
	oracle := cryptopals.Challenge12EncryptionOracle()
	blockSize, hiddenTextSize := cryptopals.DetectBlockSizeFromOracle(oracle)
	fmt.Printf("Detected block size of %d, hidden text size of %d\n", blockSize, hiddenTextSize)
	isECB := cryptopals.Challenge11DetectECB(oracle)
	if isECB {
		fmt.Println("Yes, it's ECB")
	}
	decrypt := cryptopals.Challenge12DecryptECBFromOracle(blockSize, hiddenTextSize, oracle)
	fmt.Printf("Decrypted: %s\n", string(decrypt))
	return nil
}

func challenge13(c *cli.Context) error {
	var secretKey [16]byte
	rand.Read(secretKey[:])

	c13Codec := cryptopals.NewC13Codec(secretKey[:])
	// for the block "admin&uid=10&rol"
	wordAdminCipherText := c13Codec.EncodeProfileFor("foo@bar123admin")
	// for the correctly-padded block "=user"
	equalsUserCipherText := c13Codec.EncodeProfileFor("foo@bar1234567")
	// for the blocks "foo@bar123456&uid=10&role="
	roleEqualsCipherText := c13Codec.EncodeProfileFor("foo@bar123456")
	roleEqualsCipherText = append(roleEqualsCipherText, equalsUserCipherText[32:48]...)
	copy(roleEqualsCipherText[32:48], wordAdminCipherText[16:32])
	profile1 := c13Codec.DecryptProfile(wordAdminCipherText)
	fmt.Printf("Decrypted: %#v\n", profile1)
	profile2 := c13Codec.DecryptProfile(roleEqualsCipherText)
	fmt.Printf("Decrypted: %#v\n", profile2)
	return nil
}

func challenge14(c *cli.Context) error {
	oracle := cryptopals.Challenge14EncryptionOracle()
	blockSize := cryptopals.Challenge14DetectBlockSizeFromOracle(oracle)
	fmt.Printf("Detected block size of %d\n", blockSize)
	isECB := cryptopals.Challenge11DetectECB(oracle)
	if isECB {
		fmt.Println("Yes, it's ECB")
	}
	decrypt := cryptopals.Challenge14DecryptECBFromOracle(blockSize, oracle)
	fmt.Printf("Decrypted: %s\n", string(decrypt))
	return nil
}

func challenge16(*cli.Context) error {
	c16 := cryptopals.NewC16Thing()
	cipherText := c16.EncryptWithUserData("KadminMtrueK")
	if c16.DecryptAndCheckForAdmin(cipherText) {
		fmt.Println("win")
	} else {
		fmt.Println("lose")
	}
	cipherText[16] ^= 0x70
	cipherText[22] ^= 0x70
	cipherText[27] ^= 0x70
	if c16.DecryptAndCheckForAdmin(cipherText) {
		fmt.Println("win")
	} else {
		fmt.Println("lose")
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
			{
				Name:   "challenge12",
				Usage:  "Break ECB based on encryption oracle",
				Action: challenge12,
			},
			{
				Name:   "challenge13",
				Usage:  "ECB cut and paste",
				Action: challenge13,
			},
			{
				Name:   "challenge14",
				Usage:  "Break ECB based on harder encryption oracle",
				Action: challenge14,
			},
			// challenge 15 is just to panic when validating PKCS#7 padding
			{
				Name:   "challenge16",
				Usage:  "CBC bit-flipping attacks",
				Action: challenge16,
			},
		},
	}
}
