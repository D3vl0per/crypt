package compression_test

import (
	"testing"

	"github.com/D3vl0per/crypt/compression"
	a "github.com/stretchr/testify/assert"
)

func TestCompress(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")
	for i := 0; i <= 9; i++ {
		cmp, err := compression.GzipCompress(data, i)
		a.Nil(t, err)
		dcmp, err := compression.GzipDecompress(cmp)
		a.Nil(t, err)
		a.Equal(t, data, dcmp)
	}
}

func TestWrongLevel(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")
	_, err := compression.GzipCompress(data, 10)
	a.EqualError(t, err, "gzip: invalid compression level: 10")
}
