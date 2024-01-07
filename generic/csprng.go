package generic

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
)

// CSPRNG is a cryptographically secure pseudo-random number generator for byte slices
func CSPRNG(n int64) ([]byte, error) {
	random := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, err
	}
	return random, nil
}

// CSPRNGHex is a CSPRNG in hex format
func CSPRNGHex(n int64) (string, error) {
	rnd, err := CSPRNG(n)
	return hex.EncodeToString(rnd), err
}

// HWRng is a hardware random number generator
func HWRng(n int64) ([]byte, error) {
	file, err := os.Open("/dev/hwrng")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	random := make([]byte, n)
	if _, err = io.ReadFull(file, random); err != nil {
		return nil, err
	}
	return random, nil
}

func Rand() io.Reader {
	return rand.Reader
}
