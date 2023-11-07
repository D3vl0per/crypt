package asymmetric

import (
	"crypto/subtle"
	"errors"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/nacl/box"
)

///
/// NaCl Box Suite
///

type keypairs struct {
	PK []byte
	SK []byte
}

func GenerateBoxKeypair() (keypairs, error) {
	pk, sk, err := box.GenerateKey(generic.Rand())
	if err != nil {
		return keypairs{}, nil
	}
	
	return keypairs{
		PK: pk[:],
		SK: sk[:],
	}, nil
}

func EncryptBox(senderSK, recipientPK, plaintext []byte) ([]byte, error) {
	var recipientPublicKey [32]byte
	subtle.ConstantTimeCopy(1, recipientPublicKey[:], recipientPK)

	var senderSecretKey [32]byte
	subtle.ConstantTimeCopy(1, senderSecretKey[:], senderSK)

	sharedEncryptKey := new([32]byte)
	box.Precompute(sharedEncryptKey, &recipientPublicKey, &senderSecretKey)

	nonce_raw, err := generic.CSPRNG(24)
	if err != nil {
		return []byte{}, err
	}

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], nonce_raw)
	return box.SealAfterPrecomputation(nonce[:], plaintext, &nonce, sharedEncryptKey), nil
}

func DecryptBox(senderPK, recipientSK, ciphertext []byte) ([]byte, error) {
	var senderPublicKey [32]byte
	subtle.ConstantTimeCopy(1, senderPublicKey[:], senderPK)

	var recipientSecretKey [32]byte
	subtle.ConstantTimeCopy(1, recipientSecretKey[:], recipientSK)

	var sharedDecryptKey [32]byte
	box.Precompute(&sharedDecryptKey, &senderPublicKey, &recipientSecretKey)

	var decryptNonce [24]byte
	subtle.ConstantTimeCopy(1, decryptNonce[:], ciphertext[:24])
	decrypted, ok := box.OpenAfterPrecomputation(nil, ciphertext[24:], &decryptNonce, &sharedDecryptKey)
	if !ok {
		return []byte{}, errors.New("decryption error")
	}
	return decrypted, nil
}
