package hash_test

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/hash"
	a "github.com/stretchr/testify/assert"
	r "github.com/stretchr/testify/require"
)

func TestBlake256(t *testing.T) {
	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expected := []byte{32, 109, 96, 136, 177, 62, 96, 1, 20, 103, 183, 90, 60, 235, 88, 246, 192, 122, 156, 107, 186, 36, 51, 3, 141, 52, 76, 81, 98, 229, 179, 237}
	hash, err := hash.Blake256(data)
	t.Log(hash)
	r.NoError(t, err)
	r.Equal(t, expected, hash)
}

func TestBlake512(t *testing.T) {
	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expected := []byte{119, 40, 57, 190, 223, 104, 229, 179, 37, 38, 116, 236, 59, 79, 64, 38, 242, 100, 128, 101, 147, 40, 14, 159, 186, 100, 251, 182, 206, 58, 244, 200, 26, 133, 123, 65, 131, 213, 220, 248, 152, 111, 73, 93, 126, 181, 139, 26, 48, 40, 254, 156, 254, 108, 19, 47, 92, 67, 209, 60, 127, 148, 155, 39}
	hash, err := hash.Blake512(data)
	t.Log(hash)
	r.NoError(t, err)
	r.Equal(t, expected, hash)
}

func TestHMACVerify(t *testing.T) {
	key_1 := []byte("SuperMegaSecretKey")
	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expected := "185d9e682b053bbc996325266de43541c198df70e81bc2a9a60793832ad0e9c246b11994ea768af413b97f339ae501c220188a194c734f937e816760780381cf"

	result, err := hash.HmacVerify(key_1, data, expected)
	r.NoError(t, err)
	a.True(t, result)
}

func TestHMACGen(t *testing.T) {
	key_1 := []byte("SuperMegaSecretKey")
	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expected, err := hex.DecodeString("185d9e682b053bbc996325266de43541c198df70e81bc2a9a60793832ad0e9c246b11994ea768af413b97f339ae501c220188a194c734f937e816760780381cf")
	r.NoError(t, err)

	result, err := hash.HmacGen(key_1, data)
	r.NoError(t, err)
	r.Equal(t, expected, result)
}

func TestHMACCheckSmallKeyError(t *testing.T) {
	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expected := "185d9e682b053bbc996325266de43541c198df70e81bc2a9a60793832ad0e9c246b11994ea768af413b97f339ae501c220188a194c734f937e816760780381cf"
	key_1 := []byte("Super")

	result, err := hash.HmacVerify(key_1, data, expected)
	r.EqualError(t, err, "key length is unsecurely short")
	a.False(t, result)
}

func TestHMACCheckNullKeyError(t *testing.T) {
	data := []byte("m82yeNhzBX6xKmyTqW70M4Cw9bNaZYYYRxbYgFSSXQG7hDPvQx2Q7anSWTgCshvh")
	expected := "185d9e682b053bbc996325266de43541c198df70e81bc2a9a60793832ad0e9c246b11994ea768af413b97f339ae501c220188a194c734f937e816760780381cf"
	key_1 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	result, err := hash.HmacVerify(key_1, data, expected)
	r.EqualError(t, err, "key is all zero")
	a.False(t, result)
}
