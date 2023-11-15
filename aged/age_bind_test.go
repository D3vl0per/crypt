package aged_test

import (
	"testing"

	"filippo.io/age"
	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/compression"
	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

type chains struct {
	secretKey1    *age.X25519Identity
	publicKey1    *age.X25519Identity
	publicKey2    *age.X25519Identity
	wrongKeypair  *age.X25519Identity
	keychain      aged.Keychain
	keychain2     aged.Keychain
	keychainWrong aged.Keychain
	plainData     []byte
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

	keychain, err := aged.SetupKeychain(aged.KeychainSetup{
		SecretKey:     secretKey1.String(),
		PublicKeys:    []string{publicKey1.Recipient().String(), publicKey2.Recipient().String()},
		SelfRecipient: true,
	})
	r.NoError(t, err)

	keychain2, err := aged.SetupKeychain(aged.KeychainSetup{
		SecretKey:     publicKey1.String(),
		PublicKeys:    []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()},
		SelfRecipient: true,
	})
	r.NoError(t, err)

	keychainWrong, err := aged.SetupKeychain(aged.KeychainSetup{
		SecretKey:     wrongKeypair.String(),
		PublicKeys:    []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()},
		SelfRecipient: true,
	})
	r.NoError(t, err)

	plainData, err := generic.CSPRNG(128)
	r.NoError(t, err)

	return chains{
		secretKey1:    secretKey1,
		publicKey1:    publicKey1,
		publicKey2:    publicKey2,
		wrongKeypair:  wrongKeypair,
		keychain:      keychain,
		keychain2:     keychain2,
		keychainWrong: keychainWrong,
		plainData:     plainData,
	}
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

func TestKeychainImportExport(t *testing.T) {
	keychain := keychainInit(t)

	s := aged.KeychainSetup{
		SecretKey:     keychain.keychain.KeychainExportSecretKey(),
		PublicKeys:    keychain.keychain.KeychainExport(),
		SelfRecipient: true,
	}

	t.Log("Public Keys: ", s.PublicKeys)
	t.Log("Secret Key: ", s.SecretKey)

	keychainExpected, err := aged.SetupKeychain(s)
	r.NoError(t, err)

	r.Equal(t, keychain.keychain.KeychainExportSecretKey(), keychainExpected.KeychainExportSecretKey())
	r.Equal(t, keychain.keychain.KeychainExport(), keychainExpected.KeychainExport())
}

func TestRoundTrips(t *testing.T) {
	config := keychainInit(t)

	big, err := generic.CSPRNG(10485760)
	r.NoError(t, err)

	p := []aged.Parameters{
		// No compress, No obfuscator
		{
			Data:        config.plainData,
			Obfuscation: false,
			Compress:    false,
		},
		// No compress, obfuscate
		{
			Data:        config.plainData,
			Obfuscator:  &aged.AgeV1Obf{},
			Obfuscation: true,
			Compress:    false,
		},
		// Compress with Gzip, no obfuscate
		{
			Data:        config.plainData,
			Obfuscation: false,
			Compressor:  &compression.Gzip{},
			Compress:    true,
		},
		// Compress with Gzip, obfuscate
		{
			Data:        config.plainData,
			Obfuscator:  &aged.AgeV1Obf{},
			Obfuscation: true,
			Compressor:  &compression.Gzip{},
			Compress:    true,
		},
		// Compress with Zstd, no obfuscate
		{
			Data:        config.plainData,
			Obfuscation: false,
			Compressor:  &compression.Zstd{},
			Compress:    true,
		},
		// Compress with Zstd, obfuscate
		{
			Data:        config.plainData,
			Obfuscator:  &aged.AgeV1Obf{},
			Obfuscation: true,
			Compressor:  &compression.Zstd{},
			Compress:    true,
		},
		// Compress with Flate, no obfuscate
		{
			Data:        config.plainData,
			Obfuscation: false,
			Compressor:  &compression.Flate{},
			Compress:    true,
		},
		// Compess with Flate, obfuscate
		{
			Data:        config.plainData,
			Obfuscator:  &aged.AgeV1Obf{},
			Obfuscation: true,
			Compressor:  &compression.Flate{},
			Compress:    true,
		},
		// Compress with Zlib, no obfuscate
		{
			Data:        config.plainData,
			Obfuscation: false,
			Compressor:  &compression.Zlib{},
			Compress:    true,
		},
		// Compress with Zlib, obfuscate
		{
			Data:        config.plainData,
			Obfuscator:  &aged.AgeV1Obf{},
			Obfuscation: true,
			Compressor:  &compression.Zlib{},
			Compress:    false,
		},
		// Compress big file with Zstd, obfuscate
		{
			Data:        big,
			Obfuscator:  &aged.AgeV1Obf{},
			Obfuscation: true,
			Compressor:  &compression.Zlib{},
			Compress:    true,
		},
	}

	for _, encryptParam := range p {

		decryptParam := encryptParam
		encryptPwdParam := encryptParam
		decryptPwdParam := encryptPwdParam

		var err error

		decryptParam.Data, err = config.keychain.Encrypt(encryptParam)
		r.NoError(t, err, "Encryption without error")
		t.Logf("Original size:%d Processed size: %d", len(encryptParam.Data), len(decryptParam.Data))

		decryptedData, err2 := config.keychain.Decrypt(decryptParam)
		r.NoError(t, err2, "Decryption without error")
		r.Equal(t, encryptParam.Data, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

		decryptedData2, err3 := config.keychain2.Decrypt(decryptParam)
		r.NoError(t, err3, "Decryption two without error")
		r.Equal(t, encryptParam.Data, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

		decryptedData3, err4 := config.keychainWrong.Decrypt(decryptParam)
		r.Equal(t, []byte{}, decryptedData3)
		r.EqualError(t, err4, "no identity matched any of the recipients")


		pwd, err := generic.CSPRNG(32)
		r.NoError(t, err)

		decryptPwdParam.Data, err = aged.EncryptWithPwd(encryptPwdParam, string(pwd))
		r.NoError(t, err, "Encryption without error")
		t.Logf("Pwd protected data: %d", decryptPwdParam.Data)

		decryptedPwdData, err := aged.DecryptWithPwd(decryptPwdParam, string(pwd))
		r.NoError(t, err, "Decryption without error")
		r.Equal(t, encryptPwdParam.Data, decryptedPwdData)
	}
}

func TestWrongSecretKeyKeyringSetup(t *testing.T) {
	keychain := keychainInit(t)

	s := aged.KeychainSetup{
		SecretKey:     "correct horse battery staple",
		PublicKeys:    []string{keychain.publicKey1.Recipient().String(), keychain.publicKey2.Recipient().String()},
		SelfRecipient: true,
	}

	_, err := aged.SetupKeychain(s)
	r.Error(t, err)
}

func TestWrongPublicKeyKeyringSetup(t *testing.T) {
	keychain := keychainInit(t)

	s := aged.KeychainSetup{
		SecretKey:     keychain.keychain.KeychainExportSecretKey(),
		PublicKeys:    []string{keychain.publicKey1.Recipient().String(), keychain.publicKey2.Recipient().String(), "correct horse battery staple"},
		SelfRecipient: true,
	}

	_, err := aged.SetupKeychain(s)
	r.Error(t, err)
	t.Log(err.Error())
}

/*
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
		
	}
*/




