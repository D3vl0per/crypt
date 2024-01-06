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

func (s *SecretBox) Encrypt(secret, plaintext []byte) ([]byte, error) {
	if len(secret) != 32 {
		return nil, errors.New("wrong secret size")
	}

	var secretKey [32]byte
	subtle.ConstantTimeCopy(1, secretKey[:], secret)

	nonce_raw, err := generic.CSPRNG(24)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], nonce_raw)

	return secretbox.Seal(nonce[:], plaintext, &nonce, &secretKey), nil
}

func (s *SecretBox) Decrypt(secret, ciphertext []byte) ([]byte, error) {
	if len(secret) != 32 {
		return nil, errors.New("wrong secret size")
	}

	var secretKey [32]byte
	subtle.ConstantTimeCopy(1, secretKey[:], secret)

	var nonce [24]byte
	subtle.ConstantTimeCopy(1, nonce[:], ciphertext[:24])

	decrypted, ok := secretbox.Open(nil, ciphertext[24:], &nonce, &secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}

	return decrypted, nil
}

type AesCTR struct{}

func (a *AesCTR) Encrypt(key, data []byte) ([]byte, error) {

	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if generic.AllZero(iv) {
		return nil, errors.New("iv is all zero")
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func (a *AesCTR) Decrypt(key, data []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, len(data)-aes.BlockSize)
	stream := cipher.NewCTR(block, data[:aes.BlockSize])
	stream.XORKeyStream(payload, data[aes.BlockSize:])

	return payload, nil
}

type AesCBC struct{}

func (a *AesCBC) Encrypt(key, data []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if generic.AllZero(iv) {
		return nil, errors.New("iv is all zero")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func (a *AesCBC) Decrypt(key, data []byte) ([]byte, error) {
	if generic.AllZero(key) {
		return nil, errors.New("key is all zero")
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := data[aes.BlockSize:]
	iv := data[:aes.BlockSize]

	payload := make([]byte, len(data)-aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(payload, ciphertext)

	return payload, nil
}
