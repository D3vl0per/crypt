package symmetric

import (
	"crypto/subtle"
	"errors"
	"hash"
	"io"

	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type Symmetric interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}

type SymmetricStream interface {
	Encrypt(io.Reader, io.Writer) error
	Decrypt(io.Reader, io.Writer) error
}

type XChaCha20 struct{}
type Xor struct{}

type XChaCha20Stream struct {
	Key  []byte
	Hash func() hash.Hash
}

// /
// / XChaCha20-Poly1305
// /
func (x *XChaCha20) Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return []byte{}, errors.New("wrong key size")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return []byte{}, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := generic.Rand().Read(nonce); err != nil {
		panic(err)
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (x *XChaCha20) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return []byte{}, errors.New("wrong secret size")
	}

	aead, err := chacha20poly1305.NewX(key)
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

// /
// / XOR
// /
func (x *Xor) Encrypt(key, payload []byte) ([]byte, error) {
	if len(payload) != len(key) {
		return []byte{}, errors.New("insecure xor operation, key and payload length need to be equal")
	}

	xored := make([]byte, len(payload))
	subtle.XORBytes(xored, payload, key)

	if len(payload) != len(xored) || len(key) != len(xored) {
		return []byte{}, errors.New("xored array length mismatch")
	}

	if generic.AllZero(xored) {
		return []byte{}, errors.New("xored array has just zeroes")
	}

	return xored, nil
}

func (x *Xor) Decrypt(key, payload []byte) ([]byte, error) {
	return x.Encrypt(key, payload)
}

// /
// / XChaCha20-Poly1305 Age Stream
// /
func (x *XChaCha20Stream) Encrypt(in io.Reader, out io.Writer) error {
	if len(x.Key) != chacha20poly1305.KeySize {
		return errors.New("wrong key size")
	}

	var str stream
	if x.Hash == nil {
		str = stream{
			Hash: sha3.New384,
		}
	} else {
		str = stream{Hash: x.Hash}
	}
	w, err := str.writer(out, x.Key)
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

func (x *XChaCha20Stream) Decrypt(in io.Reader, out io.Writer) error {
	if len(x.Key) != chacha20poly1305.KeySize {
		return errors.New("wrong key size")
	}

	var str stream
	if x.Hash == nil {
		str = stream{
			Hash: sha3.New384,
		}
	} else {
		str = stream{Hash: x.Hash}
	}

	r, err := str.reader(in, x.Key)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, r); err != nil {
		return err
	}
	return nil
}

type stream struct {
	Hash func() hash.Hash
}

func (s *stream) reader(src io.Reader, key []byte) (io.Reader, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, errors.New("failed to read nonce")
	}

	streamerKey, err := s.key(key, nonce)
	if err != nil {
		return nil, err
	}

	return aged.NewReader(streamerKey, src)
}

func (s *stream) writer(dst io.Writer, key []byte) (io.WriteCloser, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := generic.Rand().Read(nonce); err != nil {
		return nil, err
	}

	if _, err := dst.Write(nonce); err != nil {
		return nil, err
	}

	streamerKey, err := s.key(key, nonce)
	if err != nil {
		return nil, err
	}

	return aged.NewWriter(streamerKey, dst)
}

func (s *stream) key(fileKey, nonce []byte) ([]byte, error) {
	h := hkdf.New(s.Hash, fileKey, nonce, []byte("payload"))
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		return nil, err
	}
	if generic.AllZero(streamKey) {
		return nil, errors.New("streamer key is all zero")
	}
	return streamKey, nil
}
