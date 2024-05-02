package hash_test

import (
	"os"
	"testing"

	"github.com/D3vl0per/crypt/hash"
	r "github.com/stretchr/testify/require"
)

func TestReadFileContentAndHash(t *testing.T) {

	data := []byte("I'd just like to interject for a moment.")
	b256 := hash.Blake2b256{}
	expectedHash, err := b256.Hash(data)
	r.NoError(t, err)

	tempFile, err := os.CreateTemp("", "validate.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	err = tempFile.Sync()
	r.NoError(t, err)
	err = tempFile.Close()
	r.NoError(t, err)

	result, err := hash.ReadFileContentAndHash(&b256, tempFile.Name())
	r.NoError(t, err)
	r.Equal(t, expectedHash, result)
}

/*
func TestReadFileContentAndHmac(t *testing.T) {

	data := []byte("I'd just like to interject for a moment.")
	key, err := generic.CSPRNG(32)
	r.NoError(t, err)

	b256 := hash.Blake2b256{
		HmacSecret: key,
	}
	expectedHash, err := b256.Hash(data)
	r.NoError(t, err)

	tempFile, err := os.CreateTemp("", "validate_hmac.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	err = tempFile.Sync()
	r.NoError(t, err)
	err = tempFile.Close()
	r.NoError(t, err)

	result, err := hash.ReadFileContentAndHmac(&b256, tempFile.Name())
	r.NoError(t, err)
	r.Equal(t, expectedHash, result)
}
*/
