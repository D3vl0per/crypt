package age_test

import (
	"testing"

	"github.com/D3vl0per/crypt/age"
	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
)

var (
	keychain, keychain2, keychainWrong age.Keychain
	plainData                          []byte = []byte("4ukxipMYfoXNbaEClwKAQHz4kHLQHoIh Correct Horse Battery Staple l44zAP9dBPk1OyUxH7Vyfhwuk76kq1QZ")
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
	a.Nil(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, false, false)
	a.Nil(t, err2, "Decryption without error")
	a.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, false, false)
	a.Nil(t, err3, "Decryption two without error")
	a.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, false, false)
	a.Equal(t, []byte{}, decryptedData3)
	a.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptCompress(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, true, false)
	a.Nil(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, true, false)
	a.Nil(t, err2, "Decryption without error")
	a.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, true, false)
	a.Nil(t, err3, "Decryption two without error")
	a.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, true, false)
	a.Equal(t, []byte{}, decryptedData3)
	a.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptObfuscated(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, false, true)
	a.Nil(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, false, true)
	a.Nil(t, err2, "Decryption without error")
	a.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, false, true)
	a.Nil(t, err3, "Decryption two without error")
	a.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, false, true)
	a.Equal(t, []byte{}, decryptedData3)
	a.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptBigFile(t *testing.T) {
	plainText, err := generic.CSPRNG(10485760)
	a.Nil(t, err, "Encryption without error")
	cipherData, err := keychain.Encrypt(plainText, false, true)
	a.Nil(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainText), len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, false, true)
	a.Nil(t, err2, "Decryption without error")
	a.Equal(t, plainText, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, false, true)
	a.Nil(t, err3, "Decryption two without error")
	a.Equal(t, plainText, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, false, true)
	a.Equal(t, []byte{}, decryptedData3)
	a.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptCompressAndObfuscated(t *testing.T) {
	cipherData, err := keychain.Encrypt(plainData, true, true)
	a.Nil(t, err, "Encryption without error")
	t.Logf("Size:%d", len(cipherData))

	decryptedData, err2 := keychain.Decrypt(cipherData, true, true)
	a.Nil(t, err2, "Decryption without error")
	a.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychain2.Decrypt(cipherData, true, true)
	a.Nil(t, err3, "Decryption two without error")
	a.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychainWrong.Decrypt(cipherData, true, true)
	a.Equal(t, []byte{}, decryptedData3)
	a.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptWithPwd(t *testing.T) {
	key, err := generic.CSPRNG(32)
	a.Nil(t, err, "CSPRNG without error")

	cipherData, err := age.EncryptWithPwd(string(key), plainData, true, true)
	a.Nil(t, err, "Encryption without error")
	t.Logf("Size: %d", len(cipherData))

	decryptedData, err := age.DecryptWithPwd(string(key), cipherData, true, true)
	a.Nil(t, err, "Decryption without error")
	a.Equal(t, plainData, decryptedData)
}

func TestGenKeypair(t *testing.T) {
	_, err := age.GenKeypair()
	a.Nil(t, err)
}

func TestKeychain(t *testing.T) {
	identity, _ := age.GenKeypair()
	a.Equal(t, len(identity.Recipient().String()), 62)
	a.Equal(t, len(identity.String()), 74)
}
