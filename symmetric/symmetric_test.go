package symmetric_test

import (
	"bytes"
	"encoding/hex"

	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/symmetric"
	r "github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestStreamXChaCha20(t *testing.T) {
	plainText := []byte("https://xkcd.com/936/")
	out := &bytes.Buffer{}
	in := bytes.NewReader(plainText)

	key, err := generic.CSPRNG(chacha20poly1305.KeySize)
	r.NoError(t, err)

	sym := symmetric.XChaCha20Stream{
		Key: key,
	}

	err = sym.Encrypt(in, out)
	r.NoError(t, err)

	t.Logf("Key: %s", hex.EncodeToString(key))
	t.Logf("Encrypted file size: %d\n", out.Len())
	t.Logf("Encrypted value: %s", hex.EncodeToString(out.Bytes()))

	rr := bytes.NewReader(out.Bytes())
	out2 := &bytes.Buffer{}

	sym2 := symmetric.XChaCha20Stream{
		Key: key,
	}

	r.NoError(t, sym2.Decrypt(rr, out2))

	t.Logf("Decrypted file size: %d\n", out2.Len())
	t.Logf("Decrypted value: %s", out2.String())
	r.Equal(t, out2.Bytes(), plainText)
}

func TestXChaCha20(t *testing.T) {
	secret, err := hex.DecodeString("aec26928fb2a0177806eb76b22a116b2d3d2471ac44ffe9f27aee1da3839eff1")
	r.NoError(t, err)
	payload := []byte("https://xkcd.com/936/")

	sym := symmetric.XChaCha20{}

	ciphertext, err := sym.Encrypt(secret, payload)
	r.NoError(t, err)

	sym2 := symmetric.XChaCha20{}

	plaintext, err := sym2.Decrypt(secret, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)
}

func TestXOR(t *testing.T) {
    a := []byte{0x0f, 0x1a, 0x2b, 0x3c}
    b := []byte{0x2a, 0x1b, 0x0c, 0x3d}

	sym := symmetric.Xor{}
    expected := []byte{0x25, 0x01, 0x27, 0x01}
    result, err := sym.Encrypt(a, b)
    r.NoError(t, err)

    r.Equal(t, expected, result)
}