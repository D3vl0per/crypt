package hash

import (
	"errors"
	"hash"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var ErrHmacSecretNil = errors.New("HMAC secret is nil")

type Algorithms interface {
	// data
	Hash([]byte) ([]byte, error)
	// plaintext, expectedHash
	ValidateHash([]byte, []byte) (bool, error)
	// data
	Hmac([]byte) ([]byte, error)
	// data, expectedHash
	ValidateHmac([]byte, []byte) (bool, error)
}

type Blake2b256 struct {
	HmacSecret []byte
}
type Blake2b384 struct {
	HmacSecret []byte
}
type Blake2b512 struct {
	HmacSecret []byte
}

type Sha3256 struct {
	HmacSecret []byte
}
type Sha3384 struct {
	HmacSecret []byte
}
type Sha3512 struct {
	HmacSecret []byte
}

type Shake128 struct {
	HmacSecret []byte
}
type Shake256 struct {
	HmacSecret []byte
}

///
/// Blake2b-256
///

func (b *Blake2b256) Hash(data []byte) ([]byte, error) {
	return hashBlake2b(blake2b.Size256, nil, data)
}

func (b *Blake2b256) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size256, nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b256) Hmac(data []byte) ([]byte, error) {
	if b.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	return hashBlake2b(blake2b.Size256, b.HmacSecret, data)
}

func (b *Blake2b256) ValidateHmac(data, expectedHash []byte) (bool, error) {
	if b.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}
	hashed, err := hashBlake2b(blake2b.Size256, b.HmacSecret, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

///
/// Blake2b-384
///

func (b *Blake2b384) Hash(data []byte) ([]byte, error) {
	return hashBlake2b(blake2b.Size384, nil, data)
}

func (b *Blake2b384) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size384, nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b384) Hmac(data []byte) ([]byte, error) {
	if b.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	return hashBlake2b(blake2b.Size384, b.HmacSecret, data)
}

func (b *Blake2b384) ValidateHmac(data, expectedHash []byte) (bool, error) {
	if b.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}
	hashed, err := hashBlake2b(blake2b.Size384, b.HmacSecret, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

///
/// Blake2b-512
///

func (b *Blake2b512) Hash(data []byte) ([]byte, error) {
	return hashBlake2b(blake2b.Size, nil, data)
}

func (b *Blake2b512) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size, nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (b *Blake2b512) Hmac(data []byte) ([]byte, error) {
	if b.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	return hashBlake2b(blake2b.Size, b.HmacSecret, data)
}

func (b *Blake2b512) ValidateHmac(data, expectedHash []byte) (bool, error) {
	if b.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}
	hashed, err := hashBlake2b(blake2b.Size, b.HmacSecret, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashBlake2b(size int, key, data []byte) ([]byte, error) {
	var err error
	var hash hash.Hash

	if key != nil {
		hash, err = blake2b.New(size, key)
		if err != nil {
			return nil, err
		}
	} else {
		hash, err = blake2b.New(size, nil)
		if err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(data); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

///
/// SHA3-256
///

func (s *Sha3256) Hash(data []byte) ([]byte, error) {
	return hashSha3256(nil, data)
}

func (s *Sha3256) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3256(nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (s *Sha3256) Hmac(data []byte) ([]byte, error) {
	if s.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	return hashSha3256(s.HmacSecret, data)
}

func (s *Sha3256) ValidateHmac(data, expectedHash []byte) (bool, error) {
	if s.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}
	hashed, err := hashSha3256(s.HmacSecret, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashSha3256(key, data []byte) ([]byte, error) {
	var err error
	var hash hash.Hash

	if key != nil {
		hash = sha3.New256()
		if _, err := hash.Write(key); err != nil {
			return nil, err
		}
	} else {
		hash = sha3.New256()
		if err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(data); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

///
/// SHA3-384
///

func (s *Sha3384) Hash(data []byte) ([]byte, error) {
	return hashSha3384(nil, data)
}

func (s *Sha3384) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3384(nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (s *Sha3384) Hmac(data []byte) ([]byte, error) {
	if s.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	return hashSha3384(s.HmacSecret, data)
}

func (s *Sha3384) ValidateHmac(data, expectedHash []byte) (bool, error) {
	if s.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}
	hashed, err := hashSha3384(s.HmacSecret, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashSha3384(key, data []byte) ([]byte, error) {
	var err error
	var hash hash.Hash

	if key != nil {
		hash = sha3.New384()
		if _, err := hash.Write(key); err != nil {
			return nil, err
		}
	} else {
		hash = sha3.New384()
		if err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(data); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

///
/// SHA3-512
///

func (s *Sha3512) Hash(data []byte) ([]byte, error) {
	return hashSha3512(nil, data)
}

func (s *Sha3512) ValidateHash(plaintext, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3512(nil, plaintext)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func (s *Sha3512) Hmac(data []byte) ([]byte, error) {
	if s.HmacSecret == nil {
		return nil, ErrHmacSecretNil
	}
	return hashSha3512(s.HmacSecret, data)
}

func (s *Sha3512) ValidateHmac(data, expectedHash []byte) (bool, error) {
	if s.HmacSecret == nil {
		return false, ErrHmacSecretNil
	}
	hashed, err := hashSha3512(s.HmacSecret, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hashed, expectedHash), nil
}

func hashSha3512(key, data []byte) ([]byte, error) {
	var err error
	var hash hash.Hash

	if key != nil {
		hash = sha3.New512()
		if _, err := hash.Write(key); err != nil {
			return nil, err
		}
	} else {
		hash = sha3.New512()
		if err != nil {
			return nil, err
		}
	}

	if _, err := hash.Write(data); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
