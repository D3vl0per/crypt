package hash_test

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/hash"
	a "github.com/stretchr/testify/assert"
)

func TestArgon2ID(t *testing.T) {
	pass := []byte("Correct Horse Battery Staple")

	blob, err := hash.Argon2ID(pass)
	a.Nil(t, err)

	isValid, err := hash.Argon2IDVerify(pass, blob.Salt, blob.Hash)
	a.Nil(t, err)
	a.True(t, isValid)
}

func TestArgon2IDCustomSalt(t *testing.T) {
	pass := []byte("Correct Horse Battery Staple")
	salt, err := generic.CSPRNG(16)
	a.Nil(t, err)

	blob, err := hash.Argon2IDCustomSalt(pass, salt)
	a.Nil(t, err)

	isValid, err := hash.Argon2IDVerify(pass, blob.Salt, blob.Hash)
	a.Nil(t, err)
	a.True(t, isValid)

	isValid, err = hash.Argon2IDVerify(pass, hex.EncodeToString(salt), blob.Hash)
	a.Nil(t, err)
	a.True(t, isValid)
}

func TestHKDF(t *testing.T) {
	secret := []byte("Correct Horse Battery Staple")
	msg := []byte("https://xkcd.com/936/")

	kdf, err := hash.HKDF(secret, msg)
	a.Nil(t, err)

	isValid, err := hash.HKDFVerify(secret, msg, kdf.Salt, kdf.Hash)
	a.Nil(t, err)
	a.True(t, isValid)
}

/*
func TestHKDFCustomSalt(t *testing.T) {
	secret := []byte("Correct Horse Battery Staple")
	msg := []byte("https://xkcd.com/936/")
	salt, err := CSPRNG(32)
	assert.Nil(t, err)

	kdf, err := HKDFCustomSalt(secret, msg, salt)
	assert.Nil(t, err)

	isValid, err := HKDFVerify(secret, msg, kdf.Salt, kdf.Hash)
	assert.Nil(t, err)
	assert.True(t, isValid)

	isValid, err = HKDFVerify(secret, msg, hex.EncodeToString(salt), kdf.Hash)
	assert.Nil(t, err)
	assert.True(t, isValid)
}
*/
