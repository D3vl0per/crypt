package hash

import (
	"encoding/hex"
	//"errors"
	"crypto/sha256"
	"io"

	"github.com/D3vl0per/crypt/generic"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	aTime       uint32 = 2
	aMemory     uint32 = 1 * 64 * 1024
	aThreads    uint8  = 4
	aKeyLen     uint32 = 32
	HKDFKeysize int    = 32
)

type keys struct {
	Salt string
	Hash string
}

// Easy to user argon2ID toolset
func Argon2IDBase(pass, salt []byte) (keys, error) {
	hash := argon2.IDKey(pass, salt, aTime, aMemory, aThreads, aKeyLen)

	return keys{
		Salt: hex.EncodeToString(salt),
		Hash: hex.EncodeToString(hash),
	}, nil
}

func Argon2IDRecreate(pass []byte, salt string) ([]byte, error) {
	salt_raw, err := hex.DecodeString(salt)
	if err != nil {
		return []byte{}, err
	}

	hash_to_validate := argon2.IDKey(pass, salt_raw, aTime, aMemory, aThreads, aKeyLen)
	return hash_to_validate, nil
}

func Argon2ID(pass []byte) (keys, error) {
	salt, err := generic.CSPRNG(16)
	if err != nil {
		return keys{}, err
	}

	return Argon2IDBase(pass, salt)
}

func Argon2IDCustomSalt(pass, salt []byte) (keys, error) {
	/*
		if len(salt) != 16 {
			return keys{}, errors.New("salt length is incorrect")
		}
	*/
	return Argon2IDBase(pass, salt)
}

func Argon2IDVerify(pass []byte, salt, hash string) (bool, error) {
	hash_to_validate, err := Argon2IDRecreate(pass, salt)
	if err != nil {
		return false, err
	}

	hash_raw, err := hex.DecodeString(hash)
	if err != nil {
		return false, err
	}

	return generic.Compare(hash_raw, hash_to_validate), nil
}

// Easy to user HKDF toolset
func HKDFBase(secret, salt, msg []byte) ([]byte, error) {
	hash := sha256.New
	kdf := hkdf.New(hash, secret, salt, msg)

	key := make([]byte, HKDFKeysize)

	_, err := io.ReadFull(kdf, key)
	if err != nil {
		return []byte{}, err
	}
	return key, nil
}

func HKDFRecreate(secret, msg []byte, salt string) ([]byte, error) {
	salt_raw, err := hex.DecodeString(salt)
	if err != nil {
		return []byte{}, err
	}

	return HKDFBase(secret, salt_raw, msg)
}

func HKDF(secret, msg []byte) (keys, error) {
	hash := sha256.New
	salt, err := generic.CSPRNG(int64(hash().Size()))
	if err != nil {
		return keys{}, err
	}

	key, err := HKDFBase(secret, salt, msg)
	if err != nil {
		return keys{}, err
	}

	return keys{
		Salt: hex.EncodeToString(salt),
		Hash: hex.EncodeToString(key),
	}, nil
}

/*
func HKDFCustomSalt(secret, salt, msg []byte) (keys, error) {

		hash := sha256.New
		if len(salt) != hash().Size(){
			return keys{}, errors.New("salt length is incorrect")
		}

		key, err := HKDFBase(secret, salt, msg)
		if err != nil {
			return keys{}, err
		}

		return keys{
			Salt: hex.EncodeToString(salt),
			Hash: hex.EncodeToString(key),
		}, nil
	}
*/
func HKDFVerify(secret, msg []byte, salt, hash string) (bool, error) {
	hash_to_validate, err := HKDFRecreate(secret, msg, salt)
	if err != nil {
		return false, err
	}

	hash_raw, err := hex.DecodeString(hash)
	if err != nil {
		return false, err
	}

	return generic.Compare(hash_raw, hash_to_validate), nil
}
