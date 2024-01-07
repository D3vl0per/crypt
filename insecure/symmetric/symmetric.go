package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/nacl/secretbox"
)

type Symmetric interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}

type SecretBox struct{}

func (s *SecretBox) Encrypt(key, payload []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}

	var secretKey [32]byte
	subtle.ConstantTimeCopy(1, secretKey[:], key)

	nonce_raw, err := generic.CSPRNG(24)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], nonce_raw)

	return secretbox.Seal(nonce[:], payload, &nonce, &secretKey), nil
}

func (s *SecretBox) Decrypt(key, payload []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size")
	}
	var secretKey [32]byte
	subtle.ConstantTimeCopy(1, secretKey[:], key)

	if len(payload) < 24 {
		return nil, errors.New("payload is too short")
	}

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], payload[:24])

	decrypted, ok := secretbox.Open(nil, payload[24:], &nonce, &secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}

	return decrypted, nil
}

type AesCTR struct{}

func (a *AesCTR) Encrypt(key, payload []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(payload))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], payload)

	return ciphertext, nil
}

func (a *AesCTR) Decrypt(key, payload []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	if len(payload) < aes.BlockSize {
		return nil, errors.New("payload is too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(payload)-aes.BlockSize)
	stream := cipher.NewCTR(block, payload[:aes.BlockSize])
	stream.XORKeyStream(plaintext, payload[aes.BlockSize:])

	return plaintext, nil
}

type AesCBC struct{}

func (a *AesCBC) Encrypt(key, payload []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	if len(payload)%aes.BlockSize != 0 {
		return nil, errors.New("payload is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(payload))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], payload)
	return ciphertext, nil
}

func (a *AesCBC) Decrypt(key, payload []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	if len(payload)%aes.BlockSize != 0 || len(payload) < aes.BlockSize {
		return nil, errors.New("payload is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := payload[aes.BlockSize:]
	iv := payload[:aes.BlockSize]

	plaintext := make([]byte, len(payload)-aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}
