package aged_test

import (
	"testing"

	"filippo.io/age"
	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

var (
	//nolint:gochecknoglobals
	//nolint:gochecknoglobals
	plainData []byte = []byte("4ukxipMYfoXNbaEClwKAQHz4kHLQHoIh Correct Horse Battery Staple l44zAP9dBPk1OyUxH7Vyfhwuk76kq1QZ")
)

type chains struct {
	secretKey1    *age.X25519Identity
	publicKey1    *age.X25519Identity
	publicKey2    *age.X25519Identity
	wrongKeypair  *age.X25519Identity
	keychain      aged.Keychain
	keychain2     aged.Keychain
	keychainWrong aged.Keychain
}

func keychainInit(t *testing.T) chains {
	secretKey1, err := aged.GenKeypair()
	r.NoError(t, err)

	publicKey1, err := aged.GenKeypair()
	r.NoError(t, err)
	publicKey2, err := aged.GenKeypair()
	r.NoError(t, err)
	wrongKeypair, err := aged.GenKeypair()
	r.NoError(t, err)

	keychain, err := aged.SetupKeychain(secretKey1.String(), []string{publicKey1.Recipient().String(), publicKey2.Recipient().String()})
	r.NoError(t, err)
	keychain2, err := aged.SetupKeychain(publicKey1.String(), []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()})
	r.NoError(t, err)
	keychainWrong, err := aged.SetupKeychain(wrongKeypair.String(), []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()})
	r.NoError(t, err)

	return chains{
		secretKey1:    secretKey1,
		publicKey1:    publicKey1,
		publicKey2:    publicKey2,
		wrongKeypair:  wrongKeypair,
		keychain:      keychain,
		keychain2:     keychain2,
		keychainWrong: keychainWrong,
	}
}

func TestEncryptAndDecryptPlain(t *testing.T) {
	keychains := keychainInit(t)

	cipherData, err := keychains.keychain.Encrypt(plainData, false, false)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychains.keychain.Decrypt(cipherData, false, false)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychains.keychain2.Decrypt(cipherData, false, false)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychains.keychainWrong.Decrypt(cipherData, false, false)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptCompress(t *testing.T) {
	keychains := keychainInit(t)

	cipherData, err := keychains.keychain.Encrypt(plainData, true, false)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychains.keychain.Decrypt(cipherData, true, false)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychains.keychain2.Decrypt(cipherData, true, false)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychains.keychainWrong.Decrypt(cipherData, true, false)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptObfuscated(t *testing.T) {
	keychains := keychainInit(t)

	cipherData, err := keychains.keychain.Encrypt(plainData, false, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainData), len(cipherData))

	decryptedData, err2 := keychains.keychain.Decrypt(cipherData, false, true)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychains.keychain2.Decrypt(cipherData, false, true)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychains.keychainWrong.Decrypt(cipherData, false, true)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptBigFile(t *testing.T) {
	keychains := keychainInit(t)

	plainText, err := generic.CSPRNG(10485760)
	r.NoError(t, err, "Encryption without error")
	cipherData, err := keychains.keychain.Encrypt(plainText, false, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Original size:%d Processed size: %d", len(plainText), len(cipherData))

	decryptedData, err2 := keychains.keychain.Decrypt(cipherData, false, true)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainText, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychains.keychain2.Decrypt(cipherData, false, true)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainText, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychains.keychainWrong.Decrypt(cipherData, false, true)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptAndDecryptCompressAndObfuscated(t *testing.T) {
	keychains := keychainInit(t)

	cipherData, err := keychains.keychain.Encrypt(plainData, true, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Size:%d", len(cipherData))

	decryptedData, err2 := keychains.keychain.Decrypt(cipherData, true, true)
	r.NoError(t, err2, "Decryption without error")
	r.Equal(t, plainData, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

	decryptedData2, err3 := keychains.keychain2.Decrypt(cipherData, true, true)
	r.NoError(t, err3, "Decryption two without error")
	r.Equal(t, plainData, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

	decryptedData3, err4 := keychains.keychainWrong.Decrypt(cipherData, true, true)
	r.Equal(t, []byte{}, decryptedData3)
	r.EqualError(t, err4, "no identity matched any of the recipients")
}

func TestEncryptWithPwd(t *testing.T) {
	key, err := generic.CSPRNG(32)
	r.NoError(t, err, "CSPRNG without error")

	cipherData, err := aged.EncryptWithPwd(string(key), plainData, true, true)
	r.NoError(t, err, "Encryption without error")
	t.Logf("Size: %d", len(cipherData))

	decryptedData, err := aged.DecryptWithPwd(string(key), cipherData, true, true)
	r.NoError(t, err, "Decryption without error")
	r.Equal(t, plainData, decryptedData)
}

func TestGenKeypair(t *testing.T) {
	_, err := aged.GenKeypair()
	r.NoError(t, err)
}

func TestKeychain(t *testing.T) {
	identity, err := aged.GenKeypair()
	r.NoError(t, err)
	a.Len(t, identity.Recipient().String(), 62)
	a.Len(t, identity.String(), 74)
}
