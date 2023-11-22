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

	// AAD test
	aad := []byte("proposal")

	sym3 := symmetric.XChaCha20{
		AdditionalData: aad,
	}

	ciphertext2, err := sym3.Encrypt(secret, payload)
	r.NoError(t, err)
	t.Log("Ciphertext AAD (hex): ", hex.EncodeToString(ciphertext2))
	t.Log("AAD (hex): ", hex.EncodeToString(aad))

	sym4 := symmetric.XChaCha20{
		AdditionalData: aad,
	}

	plaintext2, err := sym4.Decrypt(secret, ciphertext2)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext2)
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

func TestAESGCM(t *testing.T) {
	secret, err := generic.CSPRNG(32)
	r.NoError(t, err)
	payload := []byte("https://xkcd.com/936/")

	sym := symmetric.AesGCM{}

	ciphertext, err := sym.Encrypt(secret, payload)
	r.NoError(t, err)
	t.Log("Ciphertext (hex): ", hex.EncodeToString(ciphertext))

	sym2 := symmetric.AesGCM{}

	plaintext, err := sym2.Decrypt(secret, ciphertext)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext)

	// AAD test
	aad := []byte("proposal")

	sym3 := symmetric.AesGCM{
		AdditionalData: aad,
	}

	ciphertext2, err := sym3.Encrypt(secret, payload)
	r.NoError(t, err)
	t.Log("Ciphertext AAD (hex): ", hex.EncodeToString(ciphertext2))
	t.Log("AAD (hex): ", hex.EncodeToString(aad))

	sym4 := symmetric.AesGCM{
		AdditionalData: aad,
	}

	plaintext2, err := sym4.Decrypt(secret, ciphertext2)
	r.NoError(t, err)

	r.Equal(t, payload, plaintext2)
}

func TestAESGCMFails(t *testing.T) {
	secret, err := generic.CSPRNG(32)
	r.NoError(t, err)

	payload := []byte("https://xkcd.com/936/")

	sym := symmetric.AesGCM{}

	zeroKey := make([]byte, 32)
	zeroCiphertext, err := sym.Encrypt(zeroKey, payload)
	r.Error(t, err)
	r.Empty(t, zeroCiphertext)
	r.EqualError(t, err, "key is all zero")

	invalidKey := []byte("0123456789abcdef")
	invalidCiphertext, err := sym.Encrypt(invalidKey, payload)
	r.Error(t, err)
	r.Empty(t, invalidCiphertext)
	r.EqualError(t, err, "wrong key size, must be 32 bytes")

	zeroPlaintext, err := sym.Decrypt(zeroKey, zeroCiphertext)
	r.Error(t, err)
	r.Empty(t, zeroPlaintext)
	r.EqualError(t, err, "key is all zero")

	invalidCiphertext2 := []byte("ciphertext")
	invalidPlaintext, err := sym.Decrypt(invalidKey, invalidCiphertext2)
	r.Error(t, err)
	r.Empty(t, invalidPlaintext)
	r.EqualError(t, err, "wrong key size, must be 32 bytes")

	shortCiphertext := []byte("short")
	shortPlaintext, err := sym.Decrypt(secret, shortCiphertext)
	r.Error(t, err)
	r.Empty(t, shortPlaintext)
	r.EqualError(t, err, "ciphertext too short")
}
