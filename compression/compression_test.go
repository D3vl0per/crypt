package compression_test

import (
	"testing"

	"github.com/D3vl0per/crypt/compression"
	r "github.com/stretchr/testify/require"
)

func TestCompress(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")
	for i := 0; i <= 9; i++ {
		cmp, err := compression.GzipCompress(data, i)
		r.NoError(t, err)
		dcmp, err := compression.GzipDecompress(cmp)
		r.NoError(t, err)
		r.Equal(t, data, dcmp)
	}
}

func TestWrongLevel(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")
	_, err := compression.GzipCompress(data, 10)
	r.EqualError(t, err, "gzip: invalid compression level: 10")
}
