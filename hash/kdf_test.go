package hash_test

import (
	"testing"

	"github.com/D3vl0per/crypt/generic"
	"github.com/D3vl0per/crypt/hash"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestArgon2ID(t *testing.T) {
	data := []byte("Correct Horse Battery Staple")
	salt, err := generic.CSPRNG(16)
	r.NoError(t, err)
	argon := []hash.Argon2ID{
		{},
		{
			Memory: 2 * 64 * 1024,
		},
		{
			Iterations: 4,
		},
		{
			Parallelism: 8,
		},
		{
			KeyLen: 64,
		},
		{
			Salt: salt,
		},
		{
			Memory:      2 * 64 * 1024,
			Iterations:  2,
			Parallelism: 8,
			KeyLen:      64,
			Salt:        salt,
		},
	}

	for _, e := range argon {
		argonString, err := e.Hash(data)
		r.NoError(t, err)

		t.Log("Argon string: ", argonString)
		parameters, err := e.ExtractParameters(argonString)
		r.NoError(t, err)
		t.Log("Argon parameters: ", parameters)

		isValid, err := e.Validate(data, argonString)
		r.NoError(t, err)
		a.True(t, isValid)
	}

}

/*
func TestArgon2IDCustomSalt(t *testing.T) {
	pass := []byte("Correct Horse Battery Staple")
	salt, err := generic.CSPRNG(16)
	r.NoError(t, err)

	blob, err := hash.Argon2IDCustomSalt(pass, salt)
	r.NoError(t, err)

	isValid, err := hash.Argon2IDVerify(pass, blob.Salt, blob.Hash)
	r.NoError(t, err)
	a.True(t, isValid)

	isValid, err = hash.Argon2IDVerify(pass, hex.EncodeToString(salt), blob.Hash)
	r.NoError(t, err)
	a.True(t, isValid)
}
*/
/*
func TestHKDF(t *testing.T) {
	secret := []byte("Correct Horse Battery Staple")
	msg := []byte("https://xkcd.com/936/")

	kdf, err := hash.HKDF(secret, msg)
	r.NoError(t, err)

	isValid, err := hash.HKDFVerify(secret, msg, kdf.Salt, kdf.Hash)
	r.NoError(t, err)
	a.True(t, isValid)
}
*/
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
