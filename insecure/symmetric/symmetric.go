package symmetric

import (
	"crypto/aes"
	"crypto/subtle"
	"errors"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/nacl/secretbox"
)

func EncryptSecretBox(secret, plaintext []byte) ([]byte, error) {
	if len(secret) != 32 {
		return []byte{}, errors.New("wrong secret size")
	}

	var secretKey [32]byte
	subtle.ConstantTimeCopy(1, secretKey[:], secret)

	nonce_raw, err := generic.CSPRNG(24)
	if err != nil {
		return []byte{}, err
	}

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], nonce_raw)

	return secretbox.Seal(nonce[:], plaintext, &nonce, &secretKey), nil
}

func DecryptSecretBox(secret, ciphertext []byte) ([]byte, error) {
	if len(secret) != 32 {
		return []byte{}, errors.New("wrong secret size")
	}

	var secretKey [32]byte
	subtle.ConstantTimeCopy(1, secretKey[:], secret)

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], ciphertext[:24])

	decrypted, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &secretKey)
	if !ok {
		return []byte{}, errors.New("decryption error")
	}

	return decrypted, nil
}

func EncryptAESCTR(key, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted, nil
}

func DecryptAESCTR(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return []byte{}, err
	}
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted, nil
}
