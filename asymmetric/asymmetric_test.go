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

	asym := asymmetric.Ed25519{}

	err := asym.Generate()
	r.NoError(t, err)

	signature := asym.Sign(msg)
	r.NotEmpty(t, signature)

	isValid, err := asym.Verify(msg, signature)
	r.NoError(t, err)
	r.True(t, isValid)
}

/*
func TestKeyWrapping(t *testing.T) {

	pk, sk, err := GenerateEd25519Keypair()
	t.Log("Public Key", pk)
	t.Log("Secret Key", sk)
	r.NoError(t, err)

	pk_w, err := ExportECCPK(sk.Public())
	t.Log("Wrapped Public Key", pk_w)
	r.NoError(t, err)

	sk_w, err := ExportECCSK(sk)
	t.Log("Wrapped Secret Key", sk_w)
	r.NoError(t, err)

	pk_2, err := ImportECCPK(pk_w)
	r.NoError(t, err)

	sk_2, err := ImportECCSK(sk_w)
	r.NoError(t, err)

	r.Equal(t, pk, pk_2)
	r.Equal(t, sk, sk_2)
}
*/

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
