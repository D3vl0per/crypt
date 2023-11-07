package crypt

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
)

/*
	func TestGenerateBoxKeypair(t *testing.T) {
		keypair, err := GenerateBoxKeypair()
		a.Nil(t, err)
		a.Len(t, keypair.SK, 32, "generated key size not match")
		a.Len(t, keypair.PK, 32, "generated key size not match")
		a.NotEqual(t, keypair.SK, keypair.PK, "public and secret key are equal")

		t.Log("Box Secret Key:", keypair.SK)
		t.Log("Box Secret Key Hex:", hex.EncodeToString(keypair.SK))
		t.Log("Box Public Key:", keypair.PK)
		t.Log("Box Public Key Hex:", hex.EncodeToString(keypair.PK))
	}
*/
func TestGenerateEd25519Keypair(t *testing.T) {
	pk, sk, err := GenerateEd25519Keypair()
	a.Nil(t, err)
	a.Len(t, pk, 32, "generated key size not match")
	a.Len(t, sk, 64, "generated key size not match")
	a.NotEqual(t, pk, sk, "public and secret key are equal")

	t.Log("Ed25519 Secret Key:", sk)
	t.Log("Ed25519 Secret Key Hex:", hex.EncodeToString(sk))
	t.Log("Ed25519 Public Key:", pk)
	t.Log("Ed25519 Public Key Hex:", hex.EncodeToString(pk))
}

// Deterministic key generation check
func TestGenerateEd25519KeypairFromSeed(t *testing.T) {

	rng, err := generic.CSPRNG(32)
	a.Nil(t, err)

	sk, err := GenerateEd25519KeypairFromSeed(rng)
	a.Nil(t, err)

	expectedSk, err := GenerateEd25519KeypairFromSeed(rng)
	a.Nil(t, err)

	a.Equal(t, sk, expectedSk)
}

/*
	func TestE2EEEncryptDecryptBox(t *testing.T) {
		recipient, err := GenerateBoxKeypair()
		a.Nil(t, err)

		sender, err := GenerateBoxKeypair()
		a.Nil(t, err)

		plaintext := []byte("Correct Horse Battery Staple")

		ciphertext, err := EncryptBox(sender.SK, recipient.PK, plaintext)
		a.Nil(t, err)

		expectedPlaintext, err := DecryptBox(sender.PK, recipient.SK, ciphertext)
		a.Nil(t, err)

		a.Equal(t, plaintext, expectedPlaintext)
		t.Log("Ciphertext:", ciphertext)
	}
*/
func TestE2EEEd25519SignVerify(t *testing.T) {
	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")

	pk, sk, err := GenerateEd25519Keypair()
	a.Nil(t, err)

	signature := SignEd25519(sk, msg)
	a.NotEmpty(t, signature)

	isValid, err := VerifyEd25519(pk, msg, signature)
	a.Nil(t, err)
	a.True(t, isValid)
}

/*
func TestKeyWrapping(t *testing.T) {

	pk, sk, err := GenerateEd25519Keypair()
	t.Log("Public Key", pk)
	t.Log("Secret Key", sk)
	a.Nil(t, err)

	pk_w, err := ExportECCPK(sk.Public())
	t.Log("Wrapped Public Key", pk_w)
	a.Nil(t, err)

	sk_w, err := ExportECCSK(sk)
	t.Log("Wrapped Secret Key", sk_w)
	a.Nil(t, err)

	pk_2, err := ImportECCPK(pk_w)
	a.Nil(t, err)

	sk_2, err := ImportECCSK(sk_w)
	a.Nil(t, err)

	a.Equal(t, pk, pk_2)
	a.Equal(t, sk, sk_2)
}
*/

func TestGenerateEd448Keypair(t *testing.T) {
	pk, sk, err := GenerateEd448Keypair()
	a.Nil(t, err)
	a.Len(t, pk, 57, "generated key size not match")
	a.Len(t, sk, 114, "generated key size not match")
	a.NotEqual(t, pk, sk, "public and secret key are equal")

	t.Log("Ed448 Secret Key:", sk)
	t.Log("Ed448 Secret Key Hex:", hex.EncodeToString(sk))
	t.Log("Ed448 Public Key:", pk)
	t.Log("Ed448 Public Key Hex:", hex.EncodeToString(pk))
}

// Deterministic generation check
func TestGenerateEd448KeypairFromSeed(t *testing.T) {
	rng, err := generic.CSPRNG(57)
	a.Nil(t, err)

	sk, err := GenerateEd448KeypairFromSeed(rng)
	a.Nil(t, err)

	expectedSk, err := GenerateEd448KeypairFromSeed(rng)
	a.Nil(t, err)

	a.Equal(t, sk, expectedSk)
}

func TestGenerateEd448KeypairFromSeedWithWrongSeedSize(t *testing.T) {
	rng, err := generic.CSPRNG(32)
	a.Nil(t, err)

	_, err = GenerateEd448KeypairFromSeed(rng)
	a.EqualError(t, err, "seed size must be 57 bytes long")

	rng, err = generic.CSPRNG(64)
	a.Nil(t, err)

	_, err = GenerateEd448KeypairFromSeed(rng)
	a.EqualError(t, err, "seed size must be 57 bytes long")

}
