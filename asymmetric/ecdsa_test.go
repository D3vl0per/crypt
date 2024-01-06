package asymmetric_test

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/asymmetric"
	"github.com/D3vl0per/crypt/generic"
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
	r.Equal(t, asym2.PublicKey, asym.PublicKey)
}

func TestE2EEEd25519SignVerify(t *testing.T) {
	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	tests := []struct {
		name string
		asym asymmetric.Ed25519
	}{
		{
			name: "Raw keys",
		},
		{
			name: "Base64 encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.Base64{},
			},
		},
		{
			name: "UrlBase64 encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.UrlBase64{},
			},
		},
		{
			name: "RawUrlBase64 encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.RawUrlBase64{},
			},
		},
		{
			name: "RawBase64 encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.RawBase64{},
			},
		},
		{
			name: "Base32 encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.Base32{},
			},
		},
		{
			name: "PaddinglessBase32 encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.PaddinglessBase32{},
			},
		},
		{
			name: "Hex encoder",
			asym: asymmetric.Ed25519{
				Encoder: &generic.Hex{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.asym.Generate()
			r.NoError(t, err)

			signature := tt.asym.Sign(msg)
			r.NotEmpty(t, signature)
			t.Log("Signature:", signature)

			isValid, err := tt.asym.Verify(msg, signature)
			r.NoError(t, err)
			r.True(t, isValid)
		})
	}
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

func TestE2EEEd448SignVerify(t *testing.T) {
	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	tests := []struct {
		name string
		asym asymmetric.Ed448
	}{
		{
			name: "Raw keys",
		},
		{
			name: "Base64 encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.Base64{},
			},
		},
		{
			name: "UrlBase64 encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.UrlBase64{},
			},
		},
		{
			name: "RawUrlBase64 encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.RawUrlBase64{},
			},
		},
		{
			name: "RawBase64 encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.RawBase64{},
			},
		},
		{
			name: "Base32 encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.Base32{},
			},
		},
		{
			name: "PaddinglessBase32 encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.PaddinglessBase32{},
			},
		},
		{
			name: "Hex encoder",
			asym: asymmetric.Ed448{
				Encoder: &generic.Hex{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.asym.Generate()
			r.NoError(t, err)

			signature := tt.asym.Sign(msg)
			r.NotEmpty(t, signature)
			t.Log("Signature:", signature)

			isValid, err := tt.asym.Verify(msg, signature)
			r.NoError(t, err)
			r.True(t, isValid)
		})
	}
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
	r.Equal(t, asym2.PublicKey, asym.PublicKey)
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

