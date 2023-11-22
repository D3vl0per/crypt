package generic_test

import (
	s "crypto/subtle"
	"testing"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestCompare(t *testing.T) {
	rand, err := generic.CSPRNG(8)
	r.NoError(t, err)
	r.Len(t, rand, 8)
	var randEq []byte = make([]byte, 8)

	s.ConstantTimeCopy(1, randEq, rand)
	r.Equal(t, rand, randEq)

	isEq := generic.Compare(rand, randEq)
	r.True(t, isEq)
}

func TestCompareString(t *testing.T) {
	rand, err := generic.CSPRNG(8)
	r.NoError(t, err)
	r.Len(t, rand, 8)
	var randEq []byte = make([]byte, 8)

	s.ConstantTimeCopy(1, randEq, rand)
	r.Equal(t, rand, randEq)

	isEq := generic.CompareString(string(rand), string(randEq))
	r.True(t, isEq)
}
