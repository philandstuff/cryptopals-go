package main

import (
	"fmt"

	"github.com/philandstuff/cryptopals-go"
)

func main() {
	c1 := cryptopals.Englishness([]byte("etaonshrldu"))
	c2 := cryptopals.Englishness([]byte("qwertyuiop"))
	fmt.Printf("%f %f", c1, c2)
}
