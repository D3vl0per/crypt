package symmetric_test

import (
	"encoding/hex"

	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/insecure/symmetric"
	r "github.com/stretchr/testify/require"
)

func TestNaClSecretBox(t *testing.T) {
	secret, err := hex.DecodeString("aec26928fb2a0177806eb76b22a116b2d3d2471ac44ffe9f27aee1da3839eff1")
	r.NoError(t, err)

	payload := []byte("https://xkcd.com/936/")

	sym := symmetric.SecretBox{}
	ciphertext, err := sym.Encrypt(secret, payload)
	r.NoError(t, err)

	plaintext, err := sym.Decrypt(secret, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)
}


func TestAesCTR(t *testing.T) {
	key, err := generic.CSPRNG(32)
	r.NoError(t, err)

	payload := []byte("https://xkcd.com/936/")

	sym := symmetric.AesCTR{}
	ciphertext, err := sym.Encrypt(key, payload)
	r.NoError(t, err)

	plaintext, err := sym.Decrypt(key, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)
}

func TestAesCBC(t *testing.T) {
	key, err := generic.CSPRNG(32)
	r.NoError(t, err)

	payload := []byte("exampleplaintext")

	sym := symmetric.AesCBC{}
	ciphertext, err := sym.Encrypt(key, payload)
	r.NoError(t, err)

	plaintext, err := sym.Decrypt(key, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)
}
