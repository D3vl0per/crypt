package asymmetric_test

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/insecure/asymmetric"

	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestGenerateBoxKeypair(t *testing.T) {
	keypair, err := asymmetric.GenerateBoxKeypair()
	r.NoError(t, err)
	a.Len(t, keypair.SK, 32, "generated key size not match")
	a.Len(t, keypair.PK, 32, "generated key size not match")
	a.NotEqual(t, keypair.SK, keypair.PK, "public and secret key are equal")

	t.Log("Box Secret Key:", keypair.SK)
	t.Log("Box Secret Key Hex:", hex.EncodeToString(keypair.SK))
	t.Log("Box Public Key:", keypair.PK)
	t.Log("Box Public Key Hex:", hex.EncodeToString(keypair.PK))
}

func TestE2EEEncryptDecryptBox(t *testing.T) {
	recipient, err := asymmetric.GenerateBoxKeypair()
	r.NoError(t, err)

	sender, err := asymmetric.GenerateBoxKeypair()
	r.NoError(t, err)

	plaintext := []byte("Correct Horse Battery Staple")

	ciphertext, err := asymmetric.EncryptBox(sender.SK, recipient.PK, plaintext)
	r.NoError(t, err)

	expectedPlaintext, err := asymmetric.DecryptBox(sender.PK, recipient.SK, ciphertext)
	r.NoError(t, err)

	r.Equal(t, expectedPlaintext, plaintext)
	t.Log("Ciphertext:", ciphertext)
}
