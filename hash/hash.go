package hash

import (
	"hash"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type Algorithms interface {
	Hash([]byte) ([]byte, error)
	ValidateHash([]byte, []byte) (bool, error)
	Hmac([]byte, []byte) ([]byte, error)
	ValidateHmac([]byte, []byte, []byte) (bool, error)
}

type Blake2b256 struct{}
type Blake2b384 struct{}
type Blake2b512 struct{}

type Sha3256 struct{}
type Sha3384 struct{}
type Sha3512 struct{}

type Shake128 struct{}
type Shake256 struct{}

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

func (b *Blake2b256) Hmac(key, data []byte) ([]byte, error) {
	return hashBlake2b(blake2b.Size256, key, data)
}

func (b *Blake2b256) ValidateHmac(key, data, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size256, key, data)
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

func (b *Blake2b384) Hmac(key, data []byte) ([]byte, error) {
	return hashBlake2b(blake2b.Size384, key, data)
}

func (b *Blake2b384) ValidateHmac(key, data, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size384, key, data)
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

func (b *Blake2b512) Hmac(key, data []byte) ([]byte, error) {
	return hashBlake2b(blake2b.Size, key, data)
}

func (b *Blake2b512) ValidateHmac(key, data, expectedHash []byte) (bool, error) {
	hashed, err := hashBlake2b(blake2b.Size, key, data)
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

func (s *Sha3256) Hmac(key, data []byte) ([]byte, error) {
	return hashSha3256(key, data)
}

func (s *Sha3256) ValidateHmac(key, data, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3256(key, data)
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

func (s *Sha3384) Hmac(key, data []byte) ([]byte, error) {
	return hashSha3384(key, data)
}

func (s *Sha3384) ValidateHmac(key, data, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3384(key, data)
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

func (s *Sha3512) Hmac(key, data []byte) ([]byte, error) {
	return hashSha3512(key, data)
}

func (s *Sha3512) ValidateHmac(key, data, expectedHash []byte) (bool, error) {
	hashed, err := hashSha3512(key, data)
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
