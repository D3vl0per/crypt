package generic_test

import (
	"encoding/hex"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	a "github.com/stretchr/testify/assert"
)

func TestCSPRNG(t *testing.T) {
	length := 32
	rnd, err := generic.CSPRNG(int64(length))
	a.Nil(t, err)
	a.Equal(t, len(rnd), length)
	t.Log(hex.EncodeToString(rnd))
}
