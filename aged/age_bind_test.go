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

	keychain, err := aged.SetupKeychain(aged.SetupKeychainParameters{
		SecretKey:     secretKey1.String(),
		PublicKeys:    []string{publicKey1.Recipient().String(), publicKey2.Recipient().String()},
		SelfRecipient: true,
	})
	r.NoError(t, err)

	keychain2, err := aged.SetupKeychain(aged.SetupKeychainParameters{
		SecretKey:     publicKey1.String(),
		PublicKeys:    []string{secretKey1.Recipient().String(), publicKey2.Recipient().String()},
		SelfRecipient: true,
	})
	r.NoError(t, err)

	keychainWrong, err := aged.SetupKeychain(aged.SetupKeychainParameters{
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

	sk, err := aged.GenSecretKey()
	r.NoError(t, err)

	isTrue := aged.CheckPrivateKeyFormat(sk)
	r.True(t, isTrue)
}

func TestKeychain(t *testing.T) {
	identity, err := aged.GenKeypair()
	r.NoError(t, err)
	a.Len(t, identity.Recipient().String(), 62)
	a.Len(t, identity.String(), 74)
}

func TestKeychainImportExport(t *testing.T) {
	keychain := keychainInit(t)

	s := aged.SetupKeychainParameters{
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

	tests := []struct {
		name      string
		parameter aged.Parameters
	}{
		{
			name: "No compress, No obfuscator",
			parameter: aged.Parameters{
				Data: config.plainData,
			},
		},
		{
			name: "No compress, obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Obfuscator: &aged.AgeV1Obf{},
			},
		},
		{
			name: "Compress with Gzip, no obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Compressor: &compression.Gzip{},
			},
		},
		{
			name: "Compress with Gzip, obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Obfuscator: &aged.AgeV1Obf{},
				Compressor: &compression.Gzip{},
			},
		},
		{
			name: "Compress with Zstd, no obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Compressor: &compression.Zstd{Level: compression.ZstdSpeedDefault},
			},
		},
		{
			name: "Compress with Zstd, obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Obfuscator: &aged.AgeV1Obf{},
				Compressor: &compression.Zstd{Level: compression.ZstdSpeedDefault},
			},
		},
		{
			name: "Compress with Flate, no obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Compressor: &compression.Flate{},
			},
		},
		{
			name: "Compess with Flate, obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Obfuscator: &aged.AgeV1Obf{},
				Compressor: &compression.Flate{},
			},
		},
		{
			name: "Compress with Zlib, no obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Compressor: &compression.Zlib{},
			},
		},
		{
			name: "Compress with Zlib, obfuscate",
			parameter: aged.Parameters{
				Data:       config.plainData,
				Obfuscator: &aged.AgeV1Obf{},
				Compressor: &compression.Zlib{},
			},
		},
		{
			name: "Compress big file with Zstd, obfuscate",
			parameter: aged.Parameters{
				Data:       big,
				Obfuscator: &aged.AgeV1Obf{},
				Compressor: &compression.Zlib{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decryptParam := tt.parameter
			encryptPwdParam := tt.parameter
			decryptPwdParam := encryptPwdParam

			var err error

			decryptParam.Data, err = config.keychain.Encrypt(tt.parameter)
			r.NoError(t, err, "Encryption without error")
			t.Logf("Original size:%d Processed size: %d", len(tt.parameter.Data), len(decryptParam.Data))

			decryptedData, err2 := config.keychain.Decrypt(decryptParam)
			r.NoError(t, err2, "Decryption without error")
			r.Equal(t, tt.parameter.Data, decryptedData, "Decrypted data is equal with the plaintext data by the same keychain")

			decryptedData2, err3 := config.keychain2.Decrypt(decryptParam)
			r.NoError(t, err3, "Decryption two without error")
			r.Equal(t, tt.parameter.Data, decryptedData2, "Decrypted data is equal with the plaintext data by different valid keychain")

			decryptedData3, err4 := config.keychainWrong.Decrypt(decryptParam)
			r.Nil(t, decryptedData3)
			r.EqualError(t, err4, "no identity matched any of the recipients")

			pwd, err := generic.CSPRNG(32)
			r.NoError(t, err)

			decryptPwdParam.Data, err = aged.EncryptWithPwd(encryptPwdParam, string(pwd))
			r.NoError(t, err, "Encryption without error")
			t.Logf("Pwd protected data: %d", decryptPwdParam.Data)

			decryptedPwdData, err := aged.DecryptWithPwd(decryptPwdParam, string(pwd))
			r.NoError(t, err, "Decryption without error")
			r.Equal(t, encryptPwdParam.Data, decryptedPwdData)
		})
	}
}

func TestWrongSecretKeyKeyringSetup(t *testing.T) {
	keychain := keychainInit(t)

	s := aged.SetupKeychainParameters{
		SecretKey:     "correct horse battery staple",
		PublicKeys:    []string{keychain.publicKey1.Recipient().String(), keychain.publicKey2.Recipient().String()},
		SelfRecipient: true,
	}

	_, err := aged.SetupKeychain(s)
	r.Error(t, err)
}

func TestWrongPublicKeyKeyringSetup(t *testing.T) {
	keychain := keychainInit(t)

	s := aged.SetupKeychainParameters{
		SecretKey:     keychain.keychain.KeychainExportSecretKey(),
		PublicKeys:    []string{keychain.publicKey1.Recipient().String(), keychain.publicKey2.Recipient().String(), "correct horse battery staple"},
		SelfRecipient: true,
	}

	_, err := aged.SetupKeychain(s)
	r.Error(t, err)
	t.Log(err.Error())
}

func TestKeypairFormatChecker(t *testing.T) {
	identity, err := aged.GenKeypair()
	r.NoError(t, err)

	skIsValid := aged.CheckPrivateKeyFormat(identity.String())
	t.Logf("Secret Key: %s", identity.String())
	r.True(t, skIsValid)

	pkIsValid := aged.CheckPublicKeyFormat(identity.Recipient().String())
	t.Logf("Public Key: %s", identity.Recipient().String())
	r.True(t, pkIsValid)

	skIsNotValid := aged.CheckPrivateKeyFormat("correct horse battery staple")
	r.False(t, skIsNotValid)

	pkIsNotValid := aged.CheckPublicKeyFormat("correct horse battery staple")
	r.False(t, pkIsNotValid)
}
