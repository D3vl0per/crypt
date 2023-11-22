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
		Data:        obfTestData,
		Compress:    true,
		Compressor:  &compression.Zstd{Level: 11},
		Obfuscation: false,
	})

	r.NoError(t, err)

	a.True(t, bytes.Contains(obfEncrypted, []byte("age-encryption.org/v1")))

	obfEncryptedObf, err := obfuscator.Obfuscate(obfEncrypted)
	r.NoError(t, err)
	a.False(t, bytes.Contains(obfEncryptedObf, []byte("age-encryption.org/v1")))

	obfEncryptedDeObf, err := obfuscator.Deobfuscate(obfEncryptedObf)
	r.NoError(t, err)
	a.True(t, bytes.Contains(obfEncryptedDeObf, []byte("age-encryption.org/v1")))
	r.Equal(t, obfEncryptedDeObf, obfEncrypted)

	decrypted, err := obfKeychain.Decrypt(aged.Parameters{
		Data: obfEncrypted,
		Compressor: &compression.Zstd{
			Level: 11,
		},
		Compress:    true,
		Obfuscation: false,
		Obfuscator:  &aged.AgeV1Obf{},
	})
	r.NoError(t, err)

	r.Equal(t, obfTestData, decrypted)
}
