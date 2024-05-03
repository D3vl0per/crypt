package hash_test

import (
	"os"
	"testing"

	"github.com/D3vl0per/crypt/hash"
	r "github.com/stretchr/testify/require"
)

func TestReadFileContentAndHash(t *testing.T) {

	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expectedHash := []byte{32, 109, 96, 136, 177, 62, 96,
		1, 20, 103, 183, 90, 60, 235, 88, 246, 192, 122, 156,
		107, 186, 36, 51, 3, 141, 52, 76, 81, 98, 229, 179, 237}

	tempFile, err := os.CreateTemp("", "validate.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	err = tempFile.Sync()
	r.NoError(t, err)
	err = tempFile.Close()
	r.NoError(t, err)

	b256 := hash.Blake2b256{}
	result, err := hash.ReadFileContentAndHash(&b256, tempFile.Name())
	r.NoError(t, err)
	r.Equal(t, expectedHash, result)
}

func TestReadFileContentAndHmac(t *testing.T) {

	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	key := []byte("fa430a028a6cf6678b1d52d4959af4b78364b986ad08ba79e57d03f71a35d633")
	expectedHash := []byte{141, 216, 41, 55, 227, 130, 65,
		74, 238, 19, 155, 174, 22, 46, 103, 68, 212, 184, 176,
		225, 176, 182, 94, 11, 128, 55, 85, 127, 136, 105, 14, 169}

	tempFile, err := os.CreateTemp("", "validate_hmac.txt")
	r.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write(data)
	r.NoError(t, err)

	err = tempFile.Sync()
	r.NoError(t, err)
	err = tempFile.Close()
	r.NoError(t, err)

	b256 := hash.Blake2b256{
		HmacSecret: key,
	}

	result, err := hash.ReadFileContentAndHmac(&b256, tempFile.Name())
	r.NoError(t, err)
	r.Equal(t, expectedHash, result)
}
