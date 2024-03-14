package asymmetric

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/nacl/box"
)

///
/// NaCl Box Suite
///

const (
	BoxKeySize   = 32
	BoxNonceSize = 24
)

type keypairs struct {
	PK []byte
	SK []byte
}

//nolint:golint
func GenerateBoxKeypair() (keypairs, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return keypairs{}, nil
	}

	return keypairs{
		PK: pk[:],
		SK: sk[:],
	}, nil
}

func EncryptBox(senderSK, recipientPK, plaintext []byte) ([]byte, error) {
	var recipientPublicKey [BoxKeySize]byte
	subtle.ConstantTimeCopy(1, recipientPublicKey[:], recipientPK)

	var senderSecretKey [BoxKeySize]byte
	subtle.ConstantTimeCopy(1, senderSecretKey[:], senderSK)

	sharedEncryptKey := new([BoxKeySize]byte)
	box.Precompute(sharedEncryptKey, &recipientPublicKey, &senderSecretKey)

	nonceRaw, err := generic.CSPRNG(BoxNonceSize)
	if err != nil {
		return nil, err
	}

	var nonce [BoxNonceSize]byte
	subtle.ConstantTimeCopy(1, nonce[:], nonceRaw)
	return box.SealAfterPrecomputation(nonce[:], plaintext, &nonce, sharedEncryptKey), nil
}

func DecryptBox(senderPK, recipientSK, ciphertext []byte) ([]byte, error) {
	var senderPublicKey [BoxKeySize]byte
	subtle.ConstantTimeCopy(1, senderPublicKey[:], senderPK)

	var recipientSecretKey [BoxKeySize]byte
	subtle.ConstantTimeCopy(1, recipientSecretKey[:], recipientSK)

	var sharedDecryptKey [BoxKeySize]byte
	box.Precompute(&sharedDecryptKey, &senderPublicKey, &recipientSecretKey)

	var decryptNonce [BoxNonceSize]byte
	subtle.ConstantTimeCopy(1, decryptNonce[:], ciphertext[:BoxNonceSize])
	decrypted, ok := box.OpenAfterPrecomputation(nil, ciphertext[BoxNonceSize:], &decryptNonce, &sharedDecryptKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}
