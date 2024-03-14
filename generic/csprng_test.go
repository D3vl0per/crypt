package generic_test

import (
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"

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

		r.Len(t, rndHexByte, i)
	}
}

func TestHWRng(t *testing.T) {
	length := 32
	rnd, err := generic.HWRng(int64(length))
	if err == nil {
		r.NoError(t, err)
		r.Len(t, rnd, length)
		t.Log(hex.EncodeToString(rnd))
	} else {
		switch err.Error() {
		case "open /dev/hwrng: permission denied":
			t.Skip("Hardware random number generator permission denied")
		case "open /dev/hwrng: no such file or directory":
			t.Skip("Hardware random number generator not found")
		default:
			t.Log(err)
		}
	}
}

func TestRand(t *testing.T) {
	reader := generic.Rand()
	r.Equal(t, reflect.TypeOf(reader), reflect.TypeOf(rand.Reader))
}
