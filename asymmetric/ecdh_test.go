package asymmetric_test

import (
	"testing"

	"github.com/D3vl0per/crypt/asymmetric"
	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func TestGenerateSharedSecret(t *testing.T) {
	alice := asymmetric.Curve25519{}
	hex := generic.Hex{}
	err := alice.GenerateKeypair()
	r.NoError(t, err)
	t.Log("Secret Key (Alice):", hex.Encode(alice.SecretKey))
	t.Log("Public Key (Alice):", hex.Encode(alice.PublicKey))
	r.Len(t, alice.SecretKey, 32)
	r.Len(t, alice.PublicKey, 32)

	bob := asymmetric.Curve25519{}
	err = bob.GenerateKeypair()
	r.NoError(t, err)
	t.Log("Secret Key (Bob):", hex.Encode(bob.SecretKey))
	t.Log("Public Key (Bob):", hex.Encode(bob.PublicKey))
	r.Len(t, bob.SecretKey, 32)
	r.Len(t, bob.PublicKey, 32)

	r.NotEqual(t, alice.PublicKey, bob.PublicKey)
	r.NotEqual(t, alice.SecretKey, bob.SecretKey)

	aliceSharedSecret, err := alice.GenerateSharedSecret(bob.PublicKey)
	r.NoError(t, err)
	t.Log("Shared Secret (Alice):", hex.Encode(aliceSharedSecret))
	r.Len(t, aliceSharedSecret, 32)

	bobSharedSecret, err := bob.GenerateSharedSecret(alice.PublicKey)
	r.NoError(t, err)
	t.Log("Shared Secret (Bob):", hex.Encode(bobSharedSecret))
	r.Len(t, bobSharedSecret, 32)

	r.Equal(t, aliceSharedSecret, bobSharedSecret)
}

func TestOriginalCurve25519(t *testing.T) {
	hex := generic.Hex{}
	aliceSecretKey, err := generic.CSPRNG(32)
	r.NoError(t, err)
	t.Log("Secret key (alice):", hex.Encode(aliceSecretKey))

	alicePublicKey, err := curve25519.X25519(aliceSecretKey, curve25519.Basepoint)
	r.NoError(t, err)
	t.Log("Public  key (alice):", hex.Encode(alicePublicKey))

	bobSecretKey, err := generic.CSPRNG(32)
	r.NoError(t, err)
	t.Log("Secret key (bob):", hex.Encode(bobSecretKey))

	bobPublicKey, err := curve25519.X25519(bobSecretKey, curve25519.Basepoint)
	r.NoError(t, err)
	t.Log("Public  key (bob):", hex.Encode(bobPublicKey))

	aliceSharedKey, err := curve25519.X25519(aliceSecretKey, bobPublicKey)
	r.NoError(t, err)
	t.Log("Shared key (alice):", hex.Encode(aliceSharedKey))

	bobSharedKey, err := curve25519.X25519(bobSecretKey, alicePublicKey)
	r.NoError(t, err)
	t.Log("Shared key (bob):", hex.Encode(bobSharedKey))

	r.Equal(t, aliceSharedKey, bobSharedKey)
}

func TestWrongKeys(t *testing.T) {
	alice := asymmetric.Curve25519{}
	err := alice.GenerateKeypair()
	r.NoError(t, err)

	sharedKey, err := alice.GenerateSharedSecret([]byte("wrong public key"))
	r.Nil(t, sharedKey)
	r.ErrorContains(t, err, "invalid public key")

	charlie := asymmetric.Curve25519{
		SecretKey: []byte("wrong secret key"),
	}
	sharedKey, err = charlie.GenerateSharedSecret(alice.PublicKey)
	r.Nil(t, sharedKey)
	r.ErrorContains(t, err, "invalid private key size")
}
