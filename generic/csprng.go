package generic

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"io"
)

func CSPRNG(n int64) ([]byte, error) {
	random := make([]byte, n)
	if _, err := io.ReadFull(crypto_rand.Reader, random[:]); err != nil {
		return []byte{}, err
	}
	return random, nil
}

func CSPRNGHex(n int64) (string, error) {
	rnd, err := CSPRNG(n)
	return hex.EncodeToString(rnd), err
}

func Rand() io.Reader {
	return crypto_rand.Reader
}
