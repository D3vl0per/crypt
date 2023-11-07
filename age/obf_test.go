package age_test

import (
	"bytes"
	"testing"

	"github.com/D3vl0per/crypt/age"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestObf(t *testing.T) {
	obfKeypair1, _ := age.GenKeypair()
	obfKeypair2, _ := age.GenKeypair()
	obfKeychain, _ := age.SetupKeychain(obfKeypair1.String(), []string{obfKeypair2.Recipient().String()})

	obfTestString := []byte("Testing")
	obfEncrypted, err := obfKeychain.Encrypt(obfTestString, false, false)
	r.NoError(t, err)

	a.True(t, bytes.Contains(obfEncrypted, []byte("age-encryption.org/")))

	obfEncryptedObf, err := age.ObfHeader(obfEncrypted)
	r.NoError(t, err)
	a.False(t, bytes.Contains(obfEncryptedObf, []byte("age-encryption.org/")))

	obfEncryptedDeObf, err := age.DeobfHeader(obfEncryptedObf)
	r.NoError(t, err)
	a.True(t, bytes.Contains(obfEncryptedDeObf, []byte("age-encryption.org/")))
	r.Equal(t, obfEncryptedDeObf, obfEncrypted)

	decrypted, err := obfKeychain.Decrypt(obfEncrypted, false, false)
	r.NoError(t, err)

	r.Equal(t, obfTestString, decrypted)
}
