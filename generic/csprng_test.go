package generic_test

import (
	"encoding/hex"
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
