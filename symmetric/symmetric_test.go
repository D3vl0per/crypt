package symmetric_test

import (
	"bytes"
	"encoding/hex"

	//"io"
	"testing"

	"github.com/D3vl0per/crypt/symmetric"
	a "github.com/stretchr/testify/assert"
	//"golang.org/x/crypto/chacha20poly1305"
)

func TestStreamXChaCha20(t *testing.T) {
	plainText := []byte("Black lives matter.")
	out := &bytes.Buffer{}
	in := bytes.NewReader(plainText)

	key, err := symmetric.EncryptStreamXChacha20(in, out)
	a.Nil(t, err)

	t.Logf("Key: %s", hex.EncodeToString(key))
	t.Logf("Encrypted file size: %d\n", out.Len())
	t.Logf("Encrypted value: %s", hex.EncodeToString(out.Bytes()))

	rr := bytes.NewReader(out.Bytes())
	out2 := &bytes.Buffer{}
	a.Nil(t, symmetric.DecryptStreamXChacha20(rr, out2, key))

	t.Logf("Decrypted file size: %d\n", out2.Len())
	t.Logf("Decrypted value: %s", out2.String())
	a.Equal(t, out2.Bytes(), plainText)
}

/*
// DO NOT USE

	func TestNaClSecretBox(t *testing.T) {
		secret, err := hex.DecodeString("aec26928fb2a0177806eb76b22a116b2d3d2471ac44ffe9f27aee1da3839eff1")
		assert.Nil(t, err)
		payload := []byte("https://xkcd.com/936/")

		ciphertext, err := EncryptSecretBox(secret, payload)
		assert.Nil(t, err)

		plaintext, err := DecryptSecretBox(secret, ciphertext)
		assert.Nil(t, err)

		assert.Equal(t, payload, plaintext)
	}
*/
func TestXChaCha20(t *testing.T) {
	secret, err := hex.DecodeString("aec26928fb2a0177806eb76b22a116b2d3d2471ac44ffe9f27aee1da3839eff1")
	a.Nil(t, err)
	payload := []byte("https://xkcd.com/936/")

	ciphertext, err := symmetric.EncryptXChaCha20(secret, payload)
	a.Nil(t, err)

	plaintext, err := symmetric.DecryptXChacha20(secret, ciphertext)
	a.Nil(t, err)

	a.Equal(t, payload, plaintext)
}
