package asymmetric_test

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/asymmetric"
	"github.com/D3vl0per/crypt/generic"
	"github.com/cloudflare/circl/sign/ed448"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestGenerateEd25519Keypair(t *testing.T) {
	asym := asymmetric.Ed25519{}
	err := asym.Generate()
	r.NoError(t, err)
	a.Len(t, asym.PublicKey, 32, "generated key size not match")
	a.Len(t, asym.SecretKey, 64, "generated key size not match")
	r.NotEqual(t, asym.PublicKey, asym.SecretKey, "public and secret key are equal")

	t.Log("Ed25519 Secret Key:", asym.SecretKey)
	t.Log("Ed25519 Secret Key Hex:", hex.EncodeToString(asym.SecretKey))
	t.Log("Ed25519 Public Key:", asym.PublicKey)
	t.Log("Ed25519 Public Key Hex:", hex.EncodeToString(asym.PublicKey))
}

func BenchmarkGenerateEd25519Keypair(b *testing.B) {
	asym := asymmetric.Ed25519{}
	for i := 0; i < b.N; i++ {
		err := asym.Generate()
		r.NoError(b, err)
	}
}

// Deterministic key generation check.
func TestGenerateEd25519KeypairFromSeed(t *testing.T) {
	rng, err := generic.CSPRNG(32)
	r.NoError(t, err)

	asym := asymmetric.Ed25519{}

	err = asym.GenerateFromSeed(rng)
	r.NoError(t, err)

	asym2 := asymmetric.Ed25519{}

	err = asym2.GenerateFromSeed(rng)
	r.NoError(t, err)

	r.Equal(t, asym2.SecretKey, asym.SecretKey)
	r.Equal(t, asym2.GetSecretKey(), asym.GetSecretKey())
	r.Equal(t, asym2.PublicKey, asym.PublicKey)
	r.Equal(t, asym2.GetPublicKey(), asym.GetPublicKey())
}

func TestWrongEd25519KGenerationFromSeeed(t *testing.T) {
	asym := asymmetric.Ed25519{}
	err := asym.GenerateFromSeed([]byte("wrong seed"))
	r.EqualError(t, err, "seed size must be 32 bytes long")
}

func TestWrongCryptoToKeys(t *testing.T) {
	invalidKey := "not a public key"

	algos := []asymmetric.Signing{
		&asymmetric.Ed25519{},
		&asymmetric.Ed448{},
	}

	for _, algo := range algos {
		err := algo.CryptoToPublicKey(invalidKey)
		r.ErrorIs(t, err, asymmetric.ErrPublicKeyAssert)

		err = algo.CryptoToSecretKey(invalidKey)
		r.ErrorIs(t, err, asymmetric.ErrSecretKeyAssert)

		err = algo.Generate()
		r.NoError(t, err)

		sk := algo.GetSecretKey()
		pk := algo.GetPublicKey()

		switch algo {
		case &asymmetric.Ed25519{}:
			err = algo.CryptoToPublicKey(ed25519.PrivateKey(sk).Public())
			r.NoError(t, err)
			r.Equal(t, pk, algo.GetPublicKey())

			err = algo.CryptoToSecretKey(crypto.PrivateKey(sk))
			r.NoError(t, err)
			r.Equal(t, pk, algo.GetSecretKey())

		case &asymmetric.Ed448{}:
			err = algo.CryptoToPublicKey(ed448.PrivateKey(sk).Public())
			r.NoError(t, err)
			r.Equal(t, pk, algo.GetPublicKey())

			err = algo.CryptoToSecretKey(crypto.PrivateKey(sk))
			r.NoError(t, err)
			r.Equal(t, pk, algo.GetSecretKey())
		}
	}
}

func TestImportExport(t *testing.T) {

	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	tests := []struct {
		name   string
		algo   asymmetric.Signing
		pkSize int
		skSize int
	}{
		{
			name:   "Ed25519",
			algo:   &asymmetric.Ed25519{},
			pkSize: ed25519.PublicKeySize,
			skSize: ed25519.PrivateKeySize,
		},
		{
			name:   "Ed448",
			algo:   &asymmetric.Ed448{},
			pkSize: ed448.PublicKeySize,
			skSize: ed448.PrivateKeySize,
		},
	}

	encoders := []generic.Encoder{
		nil,
		&generic.Base64{},
		&generic.URLBase64{},
		&generic.RawURLBase64{},
		&generic.RawBase64{},
		&generic.Base32{},
		&generic.PaddinglessBase32{},
		&generic.Hex{},
	}

	for _, test := range tests {
		for _, encoder := range encoders {
			testName := test.name
			if encoder != nil {
				testName = test.name + "/" + encoder.GetName()
			}
			t.Run(testName, func(t *testing.T) {
				err := test.algo.Generate()
				r.NoError(t, err)

				test.algo.SetEncoder(encoder)

				signature := test.algo.Sign(msg)
				r.NotEmpty(t, signature)
				t.Log("Signature:", signature)

				isValid, err := test.algo.Verify(msg, signature)
				r.NoError(t, err)
				r.True(t, isValid)

				r.Len(t, test.algo.GetSecretKey(), test.skSize)
				r.Len(t, test.algo.GetPublicKey(), test.pkSize)

				if test.algo.GetEncoder() == nil {

					r.Equal(t, string(test.algo.GetSecretKey()), test.algo.GetSecretKeyString())
					r.Equal(t, string(test.algo.GetPublicKey()), test.algo.GetPublicKeyString())
					r.Len(t, test.algo.GetSecretKeyString(), test.skSize)
					r.Len(t, test.algo.GetPublicKeyString(), test.pkSize)

				} else {
					encodedKey := test.algo.GetSecretKeyString()
					decodedKey, err := encoder.Decode(encodedKey)
					r.NoError(t, err)

					r.NotEqual(t, string(test.algo.GetSecretKey()), encodedKey)

					r.Equal(t, test.algo.GetSecretKey(), decodedKey)

					encodedPkKey := test.algo.GetPublicKeyString()
					decodedPkKey, err := encoder.Decode(encodedPkKey)
					r.NoError(t, err)

					r.NotEqual(t, string(test.algo.GetPublicKey()), encodedPkKey)

					r.Equal(t, test.algo.GetPublicKey(), decodedPkKey)

					signature := test.algo.Sign(msg)
					r.NotEmpty(t, signature)
					t.Log("Signature:", signature)

					decodedSignature, err := encoder.Decode(signature)
					r.NoError(t, err)

					isValid, err := test.algo.Verify(msg, string(decodedSignature))
					r.Error(t, err)
					r.False(t, isValid)
				}
			})
		}
	}
}

func TestEd25519StringImport(t *testing.T) {
	correctEcKey := asymmetric.Ed25519{}
	err := correctEcKey.Generate()
	r.NoError(t, err)

	correctEcKeyring := asymmetric.Ed25519{}

	err = correctEcKeyring.StringToSecretKey(correctEcKey.GetSecretKeyString())
	r.NoError(t, err)

	wrongEcKey, err := generic.CSPRNG(ed25519.PrivateKeySize)
	r.NoError(t, err)

	wrongEcKeyring := asymmetric.Ed25519{}

	err = wrongEcKeyring.StringToSecretKey(string(wrongEcKey))
	r.ErrorIs(t, err, asymmetric.ErrTestSigning)

	publicKeyring := asymmetric.Ed25519{}

	err = publicKeyring.StringToPublicKey(correctEcKey.GetPublicKeyString())
	r.NoError(t, err)

	r.Equal(t, correctEcKey.GetPublicKey(), publicKeyring.GetPublicKey())

	// There is no way to check if the public key is wrong
	wrongEcPkKey, err := generic.CSPRNG(ed25519.PublicKeySize)
	r.NoError(t, err)

	err = publicKeyring.StringToPublicKey(string(wrongEcPkKey))
	r.NoError(t, err)

	r.Equal(t, wrongEcPkKey, publicKeyring.GetPublicKey())
}

func TestEd25519Errors(t *testing.T) {
	asym := asymmetric.Ed25519{}
	wrongSk, err := generic.CSPRNG(ed25519.PrivateKeySize - 1)
	r.NoError(t, err)
	wrongPk, err := generic.CSPRNG(ed25519.PublicKeySize - 1)
	r.NoError(t, err)

	// Wrong secret key
	err = asym.StringToSecretKey(string(wrongSk))
	r.ErrorIs(t, err, asymmetric.ErrInvalidSecretKeySize)

	// Wrong public key
	err = asym.StringToPublicKey(string(wrongPk))
	r.ErrorIs(t, err, asymmetric.ErrInvalidPublicKeySize)

	asym2 := asymmetric.Ed25519{
		Encoder: &generic.Hex{},
	}

	goodSkSize, err := generic.CSPRNG(ed25519.PrivateKeySize)
	r.NoError(t, err)

	goodPkSize, err := generic.CSPRNG(ed25519.PublicKeySize)
	r.NoError(t, err)

	err = asym2.StringToSecretKey(string(goodSkSize))
	r.ErrorContains(t, err, "encoding")

	err = asym2.StringToPublicKey(string(goodPkSize))
	r.ErrorContains(t, err, "encoding")
}

func TestGenerateEd448Keypair(t *testing.T) {
	asym := asymmetric.Ed448{}
	err := asym.Generate()
	r.NoError(t, err)
	a.Len(t, asym.PublicKey, 57, "generated key size not match")
	a.Len(t, asym.SecretKey, 114, "generated key size not match")
	a.NotEqual(t, asym.PublicKey, asym.SecretKey, "public and secret key are equal")

	t.Log("Ed448 Secret Key:", asym.SecretKey)
	t.Log("Ed448 Secret Key Hex:", hex.EncodeToString(asym.SecretKey))
	t.Log("Ed448 Public Key:", asym.PublicKey)
	t.Log("Ed448 Public Key Hex:", hex.EncodeToString(asym.PublicKey))
}

// Deterministic generation check.
func TestGenerateEd448KeypairFromSeed(t *testing.T) {
	rng, err := generic.CSPRNG(57)
	r.NoError(t, err)

	asym := asymmetric.Ed448{}

	err = asym.GenerateFromSeed(rng)
	r.NoError(t, err)

	asym2 := asymmetric.Ed448{}

	err = asym2.GenerateFromSeed(rng)
	r.NoError(t, err)

	r.Equal(t, asym2.SecretKey, asym.SecretKey)
	r.Equal(t, asym2.GetSecretKey(), asym.GetSecretKey())
	r.Equal(t, asym2.PublicKey, asym.PublicKey)
	r.Equal(t, asym2.GetPublicKey(), asym.GetPublicKey())
}

func TestGenerateEd448KeypairFromSeedWithWrongSeedSize(t *testing.T) {
	rng, err := generic.CSPRNG(32)
	r.NoError(t, err)

	asym := asymmetric.Ed448{}

	err = asym.GenerateFromSeed(rng)
	r.EqualError(t, err, "seed size must be 57 bytes long")

	rng, err = generic.CSPRNG(64)
	r.NoError(t, err)

	asym2 := asymmetric.Ed448{}

	err = asym2.GenerateFromSeed(rng)
	r.EqualError(t, err, "seed size must be 57 bytes long")
}

func BenchmarkEcdsa(b *testing.B) {
	ed25519 := asymmetric.Ed25519{}
	b.Run("Generate Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := ed25519.Generate()
			r.NoError(b, err)
		}
	})

	ed448 := asymmetric.Ed448{}
	b.Run("Generate Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := ed448.Generate()
			r.NoError(b, err)
		}
	})
}

func TestWrongEd448KGenerationFromSeeed(t *testing.T) {
	asym := asymmetric.Ed448{}
	err := asym.GenerateFromSeed([]byte("wrong seed"))
	r.EqualError(t, err, "seed size must be 57 bytes long")
}

func TestWrongEd448ToPublicKey(t *testing.T) {
	invalidKey := "not a public key"
	asym := asymmetric.Ed448{}
	err := asym.CryptoToPublicKey(invalidKey)
	r.ErrorContains(t, err, "public key type")
}

func TestEd448StringImport(t *testing.T) {
	correctEcKey := asymmetric.Ed448{}
	err := correctEcKey.Generate()
	r.NoError(t, err)

	correctEcKeyring := asymmetric.Ed448{}

	err = correctEcKeyring.StringToSecretKey(correctEcKey.GetSecretKeyString())
	r.NoError(t, err)

	wrongEcKey, err := generic.CSPRNG(ed448.PrivateKeySize)
	r.NoError(t, err)

	wrongEcKeyring := asymmetric.Ed448{}

	err = wrongEcKeyring.StringToSecretKey(string(wrongEcKey))
	r.ErrorIs(t, err, asymmetric.ErrTestSigning)

	publicKeyring := asymmetric.Ed448{}

	err = publicKeyring.StringToPublicKey(correctEcKey.GetPublicKeyString())
	r.NoError(t, err)

	r.Equal(t, correctEcKey.GetPublicKey(), publicKeyring.GetPublicKey())

	// There is no way to check if the public key is wrong
	wrongEcPkKey, err := generic.CSPRNG(ed448.PublicKeySize)
	r.NoError(t, err)

	err = publicKeyring.StringToPublicKey(string(wrongEcPkKey))
	r.NoError(t, err)

	r.Equal(t, wrongEcPkKey, publicKeyring.GetPublicKey())
}

func TestEd448Errors(t *testing.T) {
	asym := asymmetric.Ed448{}
	wrongSk, err := generic.CSPRNG(ed448.PrivateKeySize - 1)
	r.NoError(t, err)
	wrongPk, err := generic.CSPRNG(ed448.PublicKeySize - 1)
	r.NoError(t, err)

	// Wrong secret key
	err = asym.StringToSecretKey(string(wrongSk))
	r.ErrorIs(t, err, asymmetric.ErrInvalidSecretKeySize)

	// Wrong public key
	err = asym.StringToPublicKey(string(wrongPk))
	r.ErrorIs(t, err, asymmetric.ErrInvalidPublicKeySize)

	asym2 := asymmetric.Ed448{
		Encoder: &generic.Hex{},
	}

	goodSkSize, err := generic.CSPRNG(ed448.PrivateKeySize)
	r.NoError(t, err)

	goodPkSize, err := generic.CSPRNG(ed448.PublicKeySize)
	r.NoError(t, err)

	err = asym2.StringToSecretKey(string(goodSkSize))
	r.ErrorContains(t, err, "encoding")

	err = asym2.StringToPublicKey(string(goodPkSize))
	r.ErrorContains(t, err, "encoding")
}
