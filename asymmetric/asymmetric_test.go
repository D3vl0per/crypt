package crypt

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestGenerateEd25519Keypair(t *testing.T) {
	pk, sk, err := GenerateEd25519Keypair()
	r.NoError(t, err)
	a.Len(t, pk, 32, "generated key size not match")
	a.Len(t, sk, 64, "generated key size not match")
	r.NotEqual(t, pk, sk, "public and secret key are equal")

	t.Log("Ed25519 Secret Key:", sk)
	t.Log("Ed25519 Secret Key Hex:", hex.EncodeToString(sk))
	t.Log("Ed25519 Public Key:", pk)
	t.Log("Ed25519 Public Key Hex:", hex.EncodeToString(pk))
}

// Deterministic key generation check.
func TestGenerateEd25519KeypairFromSeed(t *testing.T) {
	rng, err := generic.CSPRNG(32)
	r.NoError(t, err)

	sk, err := GenerateEd25519KeypairFromSeed(rng)
	r.NoError(t, err)

	expectedSk, err := GenerateEd25519KeypairFromSeed(rng)
	r.NoError(t, err)

	r.Equal(t, expectedSk,sk)
}

func TestE2EEEd25519SignVerify(t *testing.T) {
	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	pk, sk, err := GenerateEd25519Keypair()
	r.NoError(t, err)

	signature := SignEd25519(sk, msg)
	r.NotEmpty(t, signature)

	isValid, err := VerifyEd25519(pk, msg, signature)
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
	pk, sk, err := GenerateEd448Keypair()
	r.NoError(t, err)
	a.Len(t, pk, 57, "generated key size not match")
	a.Len(t, sk, 114, "generated key size not match")
	a.NotEqual(t, pk, sk, "public and secret key are equal")

	t.Log("Ed448 Secret Key:", sk)
	t.Log("Ed448 Secret Key Hex:", hex.EncodeToString(sk))
	t.Log("Ed448 Public Key:", pk)
	t.Log("Ed448 Public Key Hex:", hex.EncodeToString(pk))
}

// Deterministic generation check.
func TestGenerateEd448KeypairFromSeed(t *testing.T) {
	rng, err := generic.CSPRNG(57)
	r.NoError(t, err)

	sk, err := GenerateEd448KeypairFromSeed(rng)
	r.NoError(t, err)

	expectedSk, err := GenerateEd448KeypairFromSeed(rng)
	r.NoError(t, err)

	r.Equal(t, expectedSk, sk)
}

func TestGenerateEd448KeypairFromSeedWithWrongSeedSize(t *testing.T) {
	rng, err := generic.CSPRNG(32)
	r.NoError(t, err)

	_, err = GenerateEd448KeypairFromSeed(rng)
	r.EqualError(t, err, "seed size must be 57 bytes long")

	rng, err = generic.CSPRNG(64)
	r.NoError(t, err)

	_, err = GenerateEd448KeypairFromSeed(rng)
	r.EqualError(t, err, "seed size must be 57 bytes long")
}
