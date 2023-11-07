package hash

import (
	"encoding/hex"
	"errors"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/blake2b"
)

func Blake256(data []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		return []byte{}, err
	}
	h.Write(data)

	return h.Sum(nil), nil
}

func Blake512(data []byte) ([]byte, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return []byte{}, err
	}
	h.Write(data)

	return h.Sum(nil), nil
}

func HMACBase(key, data []byte) ([]byte, error) {
	if len(key) <= 16 {
		return []byte{}, errors.New("key length is unsecurely short")
	}

	if generic.AllZero(key) {
		return []byte{}, errors.New("key is all zero")
	}

	h, err := blake2b.New(64, key)
	if err != nil {
		return []byte{}, err
	}

	h.Write(data)
	return h.Sum(nil), nil
}

func HmacGen(key, data []byte) ([]byte, error) {
	return HMACBase(key, data)
}

func HmacVerify(key, data []byte, expected string) (bool, error) {
	expextedHash, err := hex.DecodeString(expected)
	if err != nil {
		return false, err
	}

	hash, err := HMACBase(key, data)
	if err != nil {
		return false, err
	}

	return generic.Compare(hash, expextedHash), nil
}
