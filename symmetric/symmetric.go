package symmetric

import (
	"errors"
	"io"

	"github.com/D3vl0per/crypt/age"
	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptXChaCha20(secret, plaintext []byte) ([]byte, error) {
	if len(secret) != chacha20poly1305.KeySize {
		return []byte{}, errors.New("wrong secret size")
	}

	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return []byte{}, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := generic.Rand().Read(nonce); err != nil {
		panic(err)
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptXChacha20(secret, ciphertext []byte) ([]byte, error) {
	if len(secret) != chacha20poly1305.KeySize {
		return []byte{}, errors.New("wrong secret size")
	}

	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return []byte{}, err
	}

	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return []byte{}, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte{}, err
	}
	return plaintext, nil
}

func XOR(payload, key []byte) ([]byte, error) {
	if len(payload) != len(key) {
		return []byte{}, errors.New("insecure xor operation, key and payload length need to equal")
	}

	xored := make([]byte, len(payload))
	for i := range payload {
		xored[i] = payload[i] ^ key[i]
	}

	if len(payload) != len(xored) || len(key) != len(xored) {
		return []byte{}, errors.New("xored array length mismatch")
	}

	return xored, nil
}

func EncryptStreamXChacha20(in io.Reader, out io.Writer) (key []byte, err error) {
	key = make([]byte, chacha20poly1305.KeySize)
	if _, err = generic.Rand().Read(key); err != nil {
		return []byte{}, err
	}

	if err = encryptXChaCha20Stream(in, out, key); err != nil {
		return []byte{}, err
	}
	return key, nil
}

func EncryptStreamXChacha20CustomKey(in io.Reader, out io.Writer, key []byte) (err error) {
	return encryptXChaCha20Stream(in, out, key)
}

func encryptXChaCha20Stream(in io.Reader, out io.Writer, key []byte) error {
	w, err := streamWriter(out, key)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}

func streamWriter(dst io.Writer, key []byte) (io.WriteCloser, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := generic.Rand().Read(nonce); err != nil {
		return nil, err
	}

	if _, err := dst.Write(nonce); err != nil {
		return nil, err
	}

	return age.NewWriter(age.StreamKey(key, nonce), dst)
}

func DecryptStreamXChacha20Custom(in io.Reader, out io.Writer, key []byte) (err error) {
	return DecryptStreamXChacha20(in, out, key)
}

func DecryptStreamXChacha20(in io.Reader, out io.Writer, key []byte) error {
	r, err := streamReader(in, key)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, r); err != nil {
		return err
	}
	return nil
}

func streamReader(src io.Reader, key []byte) (io.Reader, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, errors.New("failed to read nonce")
	}

	return age.NewReader(age.StreamKey(key, nonce), src)
}
