package asymmetric

import (
	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/curve25519"
)

type DH interface {
	GenerateKeypair() error
	GenerateSharedSecret([]byte) ([]byte, error)
}

type Curve25519 struct {
	PublicKey []byte
	SecretKey []byte
}

func (c *Curve25519) GenerateKeypair() error {
	secretKey, err := generic.CSPRNG(32)
	if err != nil {
		return err
	}
	c.SecretKey = secretKey

	publicKey, err := curve25519.X25519(secretKey, curve25519.Basepoint)
	if err != nil {
		return err
	}

	c.PublicKey = publicKey
	return nil
}

func (c *Curve25519) GenerateSharedSecret(recipientPublicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(c.SecretKey, recipientPublicKey)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}
