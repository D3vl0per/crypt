package hash

import (
	"errors"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var ErrHmacSecretNil = errors.New("HMAC secret is nil")

type Algorithms interface {
	Hash(plaintext []byte) ([]byte, error)
	ValidateHash(plaintext []byte, expectedHash []byte) (bool, error)
	Hmac(plaintext []byte) ([]byte, error)
	ValidateHmac(plaintext []byte, expectedHash []byte) (bool, error)
	SetEncoder(encoder generic.Encoder)
	GetEncoder() generic.Encoder
}

type Blake2b256 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}
type Blake2b384 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}
type Blake2b512 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}

type Sha3256 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}
type Sha3384 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}
type Sha3512 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}

type Shake128 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}
type Shake256 struct {
	HmacSecret []byte
	Encoder    generic.Encoder
}

///
/// Blake2b-256
///

func (b *Blake2b256) Hash(plaintext []byte) ([]byte, error) {
	hash, err := hashBlake2b(blake2b.Size256, nil, plaintext)
	if err != nil {
		return nil, err
	}

	return encoder(b.Encoder, hash), nil
}

func (b *Blake2b256) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hash, err := hashBlake2b(blake2b.Size256, nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hash, expectedHash), nil
}

func (b *Blake2b256) Hmac(plaintext []byte) ([]byte, error) {
	if b.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	hash, err := hashBlake2b(blake2b.Size256, b.HmacSecret, plaintext)
	if err != nil {
		return nil, err
	}

	return encoder(b.Encoder, hash), nil
}

func (b *Blake2b256) ValidateHmac(plaintext, expectedHash []byte) (bool, error) {
	if b.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}

	hashed, err := hashBlake2b(blake2b.Size256, b.HmacSecret, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b256) SetEncoder(encoder generic.Encoder) {
	b.Encoder = encoder
}

func (b *Blake2b256) GetEncoder() generic.Encoder {
	if b.Encoder == nil {
		return nil
	}

	return b.Encoder
}

///
/// Blake2b-384
///

func (b *Blake2b384) Hash(plaintext []byte) ([]byte, error) {
	hash, err := hashBlake2b(blake2b.Size384, nil, plaintext)
	if err != nil {
		return nil, err
	}

	return encoder(b.Encoder, hash), nil
}

func (b *Blake2b384) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size384, nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b384) Hmac(plaintext []byte) ([]byte, error) {
	if b.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}

	hash, err := hashBlake2b(blake2b.Size384, b.HmacSecret, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(b.Encoder, hash), nil
}

func (b *Blake2b384) ValidateHmac(plaintext, expectedHash []byte) (bool, error) {
	if b.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}

	hashed, err := hashBlake2b(blake2b.Size384, b.HmacSecret, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b384) SetEncoder(encoder generic.Encoder) {
	b.Encoder = encoder
}

func (b *Blake2b384) GetEncoder() generic.Encoder {
	if b.Encoder == nil {
		return nil
	}

	return b.Encoder
}

///
/// Blake2b-512
///

func (b *Blake2b512) Hash(plaintext []byte) ([]byte, error) {
	hash, err := hashBlake2b(blake2b.Size, nil, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(b.Encoder, hash), nil
}

func (b *Blake2b512) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size, nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b512) Hmac(plaintext []byte) ([]byte, error) {
	if b.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	hash, err := hashBlake2b(blake2b.Size, b.HmacSecret, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(b.Encoder, hash), nil
}

func (b *Blake2b512) ValidateHmac(plaintext, expectedHash []byte) (bool, error) {
	if b.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}

	hashed, err := hashBlake2b(blake2b.Size, b.HmacSecret, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashBlake2b(size int, key, plaintext []byte) ([]byte, error) {
	hash, err := blake2b.New(size, key)
	if err != nil {
		return nil, err
	}

	if _, err := hash.Write(plaintext); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (b *Blake2b512) SetEncoder(encoder generic.Encoder) {
	b.Encoder = encoder
}

func (b *Blake2b512) GetEncoder() generic.Encoder {
	if b.Encoder == nil {
		return nil
	}

	return b.Encoder
}

///
/// SHA3-256
///

func (s *Sha3256) Hash(plaintext []byte) ([]byte, error) {
	hash, err := hashSha3256(nil, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(s.Encoder, hash), nil
}

func (s *Sha3256) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3256(nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (s *Sha3256) Hmac(plaintext []byte) ([]byte, error) {
	if s.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}

	hash, err := hashSha3256(s.HmacSecret, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(s.Encoder, hash), nil
}

func (s *Sha3256) ValidateHmac(plaintext, expectedHash []byte) (bool, error) {
	if s.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}

	hashed, err := hashSha3256(s.HmacSecret, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashSha3256(key, plaintext []byte) ([]byte, error) {
	hash := sha3.New256()

	if key != nil {
		if _, err := hash.Write(key); err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(plaintext); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (s *Sha3256) SetEncoder(encoder generic.Encoder) {
	s.Encoder = encoder
}

func (s *Sha3256) GetEncoder() generic.Encoder {
	if s.Encoder == nil {
		return nil
	}
	return s.Encoder
}

///
/// SHA3-384
///

func (s *Sha3384) Hash(plaintext []byte) ([]byte, error) {
	hash, err := hashSha3384(nil, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(s.Encoder, hash), nil
}

func (s *Sha3384) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3384(nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (s *Sha3384) Hmac(plaintext []byte) ([]byte, error) {
	if s.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}

	hash, err := hashSha3384(s.HmacSecret, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(s.Encoder, hash), nil
}

func (s *Sha3384) ValidateHmac(plaintext, expectedHash []byte) (bool, error) {
	if s.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}

	hashed, err := hashSha3384(s.HmacSecret, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashSha3384(key, plaintext []byte) ([]byte, error) {
	hash := sha3.New384()

	if key != nil {
		if _, err := hash.Write(key); err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(plaintext); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (s *Sha3384) SetEncoder(encoder generic.Encoder) {
	s.Encoder = encoder
}

func (s *Sha3384) GetEncoder() generic.Encoder {
	if s.Encoder == nil {
		return nil
	}
	return s.Encoder
}

///
/// SHA3-512
///

func (s *Sha3512) Hash(plaintext []byte) ([]byte, error) {
	hash, err := hashSha3512(nil, plaintext)
	if err != nil {
		return nil, err
	}
	return encoder(s.Encoder, hash), nil
}

func (s *Sha3512) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3512(nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (s *Sha3512) Hmac(plaintext []byte) ([]byte, error) {
	if s.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}

	hash, err := hashSha3512(s.HmacSecret, plaintext)
	if err != nil {
		return nil, err
	}

	return encoder(s.Encoder, hash), nil
}

func (s *Sha3512) ValidateHmac(plaintext, expectedHash []byte) (bool, error) {
	if s.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}

	hashed, err := hashSha3512(s.HmacSecret, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashSha3512(key, plaintext []byte) ([]byte, error) {
	hash := sha3.New512()
	if key != nil {
		if _, err := hash.Write(key); err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(plaintext); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (s *Sha3512) SetEncoder(encoder generic.Encoder) {
	s.Encoder = encoder
}

func (s *Sha3512) GetEncoder() generic.Encoder {
	if s.Encoder == nil {
		return nil
	}
	return s.Encoder
}

/// utils

func encoder(encoder generic.Encoder, hash []byte) []byte {
	if encoder == nil {
		return hash
	}

	return []byte(encoder.Encode(hash))
}
