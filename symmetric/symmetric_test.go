package symmetric_test

import (
	"bytes"
	"encoding/hex"

	"testing"

	"github.com/D3vl0per/crypt/symmetric"
	r "github.com/stretchr/testify/require"
)

func TestStreamXChaCha20(t *testing.T) {
	plainText := []byte("Black lives matter.")
	out := &bytes.Buffer{}
	in := bytes.NewReader(plainText)

	key, err := symmetric.EncryptStreamXChacha20(in, out)
	r.NoError(t, err)

	t.Logf("Key: %s", hex.EncodeToString(key))
	t.Logf("Encrypted file size: %d\n", out.Len())
	t.Logf("Encrypted value: %s", hex.EncodeToString(out.Bytes()))

	rr := bytes.NewReader(out.Bytes())
	out2 := &bytes.Buffer{}
	r.NoError(t, symmetric.DecryptStreamXChacha20(rr, out2, key))

	t.Logf("Decrypted file size: %d\n", out2.Len())
	t.Logf("Decrypted value: %s", out2.String())
	r.Equal(t, out2.Bytes(), plainText)
}

func TestXChaCha20(t *testing.T) {
	secret, err := hex.DecodeString("aec26928fb2a0177806eb76b22a116b2d3d2471ac44ffe9f27aee1da3839eff1")
	r.NoError(t, err)
	payload := []byte("https://xkcd.com/936/")

	ciphertext, err := symmetric.EncryptXChaCha20(secret, payload)
	r.NoError(t, err)

	plaintext, err := symmetric.DecryptXChacha20(secret, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)
}
