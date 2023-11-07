package symmetric_test

import (
	"encoding/hex"

	"testing"

	"github.com/D3vl0per/crypt/insecure/symmetric"
	r "github.com/stretchr/testify/require"
)

func TestNaClSecretBox(t *testing.T) {
	secret, err := hex.DecodeString("aec26928fb2a0177806eb76b22a116b2d3d2471ac44ffe9f27aee1da3839eff1")
	r.NoError(t, err)

	payload := []byte("https://xkcd.com/936/")

	ciphertext, err := symmetric.EncryptSecretBox(secret, payload)
	r.NoError(t, err)

	plaintext, err := symmetric.DecryptSecretBox(secret, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)
}
