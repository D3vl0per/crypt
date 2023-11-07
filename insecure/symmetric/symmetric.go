package symmetric

import (
	"crypto/aes"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
	"github.com/D3vl0per/crypt/generic"
)

func EncryptSecretBox(secret, plaintext []byte) ([]byte, error) {
	if len(secret) != 32 {
		return []byte{}, errors.New("wrong secret size")
	}

	var secretKey [32]byte
	copy(secretKey[:], secret)

	nonce_raw, err := generic.CSPRNG(24)
	if err != nil {
		return []byte{}, err
	}

	var nonce [24]byte
	copy(nonce[:], nonce_raw)

	return secretbox.Seal(nonce[:], plaintext, &nonce, &secretKey), nil
}

func DecryptSecretBox(secret, ciphertext []byte) ([]byte, error) {
	if len(secret) != 32 {
		return []byte{}, errors.New("wrong secret size")
	}

	var secretKey [32]byte
	copy(secretKey[:], secret)

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	decrypted, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &secretKey)
	if !ok {
		return []byte{}, errors.New("decryption error")
	}

	return decrypted, nil
}

func EncryptAESCTR(key, data []byte) ([]byte){
	cipher, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}

func DecryptAESCTR(data, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}
