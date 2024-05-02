package generic_test

import (
	"testing"

	"github.com/D3vl0per/crypt/generic"
	r "github.com/stretchr/testify/require"
)

func TestCustomEncoder(t *testing.T) {
	c := &generic.Custom{}

	data := "test data"
	expected := []byte(nil)
	result, err := c.Decode(data)
	r.NoError(t, err)
	r.Equal(t, expected, result)

	c.Decoder = func(data string) ([]byte, error) {
		return []byte(data), nil
	}
	expected = []byte(data)
	result, err = c.Decode(data)
	r.NoError(t, err)
	r.Equal(t, expected, result)
	r.Equal(t, string(expected), string(result))
}
