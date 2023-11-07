package age_test

import (
	"testing"

	"github.com/D3vl0per/crypt/age"
	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

var (
	//nolint:gochecknoglobals
	keychain, keychain2, keychainWrong age.Keychain
	//nolint:gochecknoglobals
	plainData []byte = []byte("4ukxipMYfoXNbaEClwKAQHz4kHLQHoIh Correct Horse Battery Staple l44zAP9dBPk1OyUxH7Vyfhwuk76kq1QZ")
)

func init() {
	secretKey1, _ := age.GenKeypair()

	publicKey1, _ := age.GenKeypair()
	publicKey2, _ := age.GenKeypair()
	wrongKeypair, _ := age.GenKeypair()

	keychain, _ = age.SetupKeychain(secretKey1.String(), []string{publicKey1.Recipient().String(), publicKey2.Recipient().String()})
	keychain2, _ = age.SetupKeychain(publicKey1.String(), []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()})
	keychainWrong, _ = age.SetupKeychain(wrongKeypair.String(), []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()})
}

func TestEncryptAndDecryptPlain(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, false, false)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, false, false)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, false, false)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, false, false)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptCompress(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, true, false)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, true, false)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, true, false)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, true, false)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptObfuscated(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, false, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, false, true)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, false, true)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, false, true)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptBigFile(t *testing.T) {
	plainText, err := generic.CSPRNG(10485760)
	r.NoError(t, err, "Encryption without error")
	cipherData, err := keychain.Encrypt(plainText, false, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainText), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, false, true)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainText, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, false, true)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainText, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, false, true)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptCompressAndObfuscated(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, true, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Size:%d", len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, true, true)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, true, true)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, true, true)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptWithPwd(t *testing.T) {
	key, err := generic.CSPRNG(32)
	r.NoError(t, err, "CSPRNG without error")

	cipherData, err := age.EncryptWithPwd(string(key), plainData, true, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Size: %d", len(cipherData))

	decryptedData, err := age.DecryptWithPwd(string(key), cipherData, true, true)
	r.NoError(t, err, "Decryption without error")
	r.Equal(t, plainData, decryptedData)
}

func TestGenKeypair(t *testing.T) {
	_, err := age.GenKeypair()
	r.NoError(t, err)
}

func TestKeychain(t *testing.T) {
	identity, _ := age.GenKeypair()
	a.Len(t, identity.Recipient().String(), 62)
	a.Len(t, identity.String(), 74)
}
