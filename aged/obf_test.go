package aged_test

import (
	"bytes"
	"testing"

	"github.com/D3vl0per/crypt/aged"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestObf(t *testing.T) {
	obfKeypair1, err := aged.GenKeypair()
	r.NoError(t, err)
	obfKeypair2, err := aged.GenKeypair()
	r.NoError(t, err)
	obfKeychain, err := aged.SetupKeychain(obfKeypair1.String(), []string{obfKeypair2.Recipient().String()})
	r.NoError(t, err)

	obfTestString := []byte("Testing")
	obfEncrypted, err := obfKeychain.Encrypt(obfTestString, false, false)
	r.NoError(t, err)

	a.True(t, bytes.Contains(obfEncrypted, []byte("age-encryption.org/")))

	obfEncryptedObf, err := aged.ObfHeader(obfEncrypted)
	r.NoError(t, err)
	a.False(t, bytes.Contains(obfEncryptedObf, []byte("age-encryption.org/")))

	obfEncryptedDeObf, err := aged.DeobfHeader(obfEncryptedObf)
	r.NoError(t, err)
	a.True(t, bytes.Contains(obfEncryptedDeObf, []byte("age-encryption.org/")))
	r.Equal(t, obfEncryptedDeObf, obfEncrypted)

	decrypted, err := obfKeychain.Decrypt(obfEncrypted, false, false)
	r.NoError(t, err)

	r.Equal(t, obfTestString, decrypted)
}
