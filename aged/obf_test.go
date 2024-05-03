package aged_test

import (
	"bytes"
	"testing"

	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/compression"
	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestObf(t *testing.T) {
	obfKeypair1, err := aged.GenKeypair()
	r.NoError(t, err)
	obfKeypair2, err := aged.GenKeypair()
	r.NoError(t, err)
	obfuscator := aged.AgeV1Obf{}

	obfKeychain, err := aged.SetupKeychain(aged.SetupKeychainParameters{
		SecretKey:     obfKeypair1.String(),
		PublicKeys:    []string{obfKeypair2.Recipient().String()},
		SelfRecipient: true,
	})
	r.NoError(t, err)

	obfTestData, err := generic.CSPRNG(128)
	r.NoError(t, err)

	obfEncrypted, err := obfKeychain.Encrypt(aged.Parameters{
		Data:       obfTestData,
		Compressor: &compression.Zstd{Level: 11},
	})
	r.NoError(t, err)

	a.True(t, bytes.Contains(obfEncrypted, []byte("age-encryption.org/v1")))

	obfEncryptedObf, err := obfuscator.Obfuscate(obfEncrypted)
	r.NoError(t, err)
	a.False(t, bytes.Contains(obfEncryptedObf, []byte("age-encryption.org/v1")))
	t.Logf("Obfuscated: %s", obfEncryptedObf)

	obfEncryptedDeObf, err := obfuscator.Deobfuscate(obfEncryptedObf)
	r.NoError(t, err)
	a.True(t, bytes.Contains(obfEncryptedDeObf, []byte("age-encryption.org/v1")))
	t.Logf("Deobfuscated: %s", obfEncryptedDeObf)
	r.Equal(t, obfEncryptedDeObf, obfEncrypted)

	decrypted, err := obfKeychain.Decrypt(aged.Parameters{
		Data: obfEncrypted,
		Compressor: &compression.Zstd{
			Level: 11,
		},
	})
	r.NoError(t, err)
	r.Equal(t, obfTestData, decrypted)
}

var testHeader = []byte(`age-encryption.org/v1
-> X25519 Fn+P3V7rbHE0zHhIUp8RBBA1L4mFwenD+4LXYzUK4xs
m7dB/9gthq7XQU2ckuj66owRh5BxfpxDaXBrP26Od2g
-> X25519 Ta3hSORpDZJlKcJFrb/t9wh9PfO4oBNgkz0058Xrfmc
R/TdqhP2WsUExNfU2nhdQmjOcxXK1rGk6pLiw2ZKIiI
--- kGWc5uZtFP5Rg9idkZ3vrWKwl9rhEcc6Ylyl9mBRbhw
`)

func TestObfInvalid(t *testing.T) {
	obfuscator := aged.AgeV1Obf{}

	obfTestData, err := generic.CSPRNG(128)
	r.NoError(t, err)

	obfEncryptedObf, err := obfuscator.Obfuscate(obfTestData)
	r.ErrorIs(t, aged.ErrMissingFlag, err)
	r.Nil(t, obfEncryptedObf)

	obfEncryptedDeObf, err := obfuscator.Deobfuscate(obfTestData)
	r.ErrorIs(t, aged.ErrMissingFlag, err)
	r.Nil(t, obfEncryptedDeObf)

	testHeader := []byte(`age-encryption.org/v1
-> X25519 Fn+P3V7rbHE0zHhIUp8RBBA1L4mFwenD+4LXYzUK4xs
m7dB/9gthq7XQU2ckuj66owRh5BxfpxDaXBrP26Od2g
-> X25519 Ta3hSORpDZJlKcJFrb/t9wh9PfO4oBNgkz0058Xrfmc
R/TdqhP2WsUExNfU2nhdQmjOcxXK1rGk6pLiw2ZKIiI
--- kGWc5uZtFP5Rg9idkZ3vrWKwl9rhEcc6Ylyl9mBRbhw
`)

	obfEncryptedObf, err = obfuscator.Obfuscate(testHeader)
	r.NoError(t, err)

	wrongHeader := bytes.Replace(obfEncryptedObf, []byte{0, 255, 1, 254}, []byte{0, 0, 0, 0}, 1)

	deObf, err := obfuscator.Deobfuscate(wrongHeader)
	r.ErrorIs(t, err, aged.ErrMissingFlag)
	r.Nil(t, deObf)
}

func TestCustomHeaderObf(t *testing.T) {
	hex := generic.Hex{}
	custom := aged.CustomObf{
		Encoder: func(data []byte) ([]byte, error) {
			return []byte(hex.Encode(data)), nil
		},
		Decoder: func(data []byte) ([]byte, error) {
			return hex.Decode(string(data))
		},
	}

	a.True(t, bytes.Contains(testHeader, []byte("age-encryption.org/v1")))

	obf, err := custom.Obfuscate(testHeader)
	r.NoError(t, err)

	a.False(t, bytes.Contains(obf, []byte("age-encryption.org/v1")))

	deObf, err := custom.Deobfuscate(obf)
	r.NoError(t, err)
	a.True(t, bytes.Contains(deObf, []byte("age-encryption.org/v1")))
	r.Equal(t, testHeader, deObf)
}
