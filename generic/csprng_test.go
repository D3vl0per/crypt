package generic_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"crypto/rand"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestCSPRNG(t *testing.T) {
	length := 32
	rnd, err := generic.CSPRNG(int64(length))
	r.NoError(t, err)
	r.Len(t, rnd, length)
	t.Log(hex.EncodeToString(rnd))
}

func TestCSPRNGHex(t *testing.T) {
	for i := 1; i < 10; i++ {
		rndHex, err := generic.CSPRNGHex(int64(i))
		r.NoError(t, err)

		rndHexByte, err := hex.DecodeString(rndHex)
		r.NoError(t, err)

		r.Equal(t, len(rndHexByte), i)
	}
}

func TestRand(t *testing.T) {
	reader := generic.Rand()
	r.Equal(t, reflect.TypeOf(reader), reflect.TypeOf(rand.Reader))
}
