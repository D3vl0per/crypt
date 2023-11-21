package compression_test

import (
	"bytes"
	"testing"

	"github.com/D3vl0per/crypt/compression"
	"github.com/D3vl0per/crypt/generic"

	r "github.com/stretchr/testify/require"
)

func TestGzipCompressRoundTrip(t *testing.T) {
	data, err := generic.CSPRNG(256)
	r.NoError(t, err)

	for i := 0; i <= 9; i++ {
		gzip := compression.Gzip{
			Level: i,
		}
		cmp, err := gzip.Compress(data)
		r.NoError(t, err)
		dcmp, err := gzip.Decompress(cmp)
		r.NoError(t, err)
		r.Equal(t, data, dcmp)
	}
}

func TestRoundTrips(t *testing.T) {
	genericModes := []int{9, 1, 0, -1, -2}
	zstdModes := []int{11, 7, 3, 1}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Random data",
			data: []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t"),
		},
		{
			name: "Zero data",
			data: []byte("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		},
		{
			name: "One data",
			data: []byte("10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010"),
		},
	}

	for _, test := range tests {
		for _, level := range zstdModes {
			t.Run(test.name, func(t *testing.T) {
				testRoundTrip(t, &compression.Zstd{Level: level}, test.data)
			})
		}
	}

	for _, test := range tests {
		for _, level := range genericModes {
			t.Run(test.name, func(t *testing.T) {
				testRoundTrip(t, &compression.Flate{Level: level}, test.data)
				testRoundTrip(t, &compression.Zlib{Level: level}, test.data)
				testRoundTrip(t, &compression.Gzip{Level: level}, test.data)
			})
		}
	}
}

func testRoundTrip(t *testing.T, compressor compression.Compressor, data []byte) {

	// Compression with ZstdCompress function
	compressed, err := compressor.Compress(data)
	r.NoError(t, err)

	var compressedBuff bytes.Buffer
	var decompressedBuff bytes.Buffer
	reader := bytes.NewReader(data)

	// Compression with ZstdCompressStream function
	err = compressor.CompressStream(reader, &compressedBuff)
	r.NoError(t, err)

	// Compression cross-check (ZstdCompress and ZstdCompressStream)
	r.Equal(t, compressed, compressedBuff.Bytes())

	t.Log("Data sample: ", data[:16])
	t.Log("Orignal size: ", len(data))
	t.Log("Compressed size: ", compressedBuff.Len())
	t.Log("Compression mode: ", compressor.GetLevel())
	t.Log("---")
	compressedReader := bytes.NewReader(compressedBuff.Bytes())

	// Decompress with ZstdDecompress function
	decompressed, err := compressor.Decompress(compressed)
	r.NoError(t, err)

	// Decompress with ZstdStream function
	err = compressor.DecompressStream(compressedReader, &decompressedBuff)
	r.NoError(t, err)

	// Decompression cross-check (ZstdCompress and ZstdCompressStream)
	r.Equal(t, decompressed, decompressedBuff.Bytes())

	r.Len(t, decompressedBuff.Bytes(), len(data))
	r.Equal(t, decompressedBuff.Bytes(), data)

	t.Log("=============")
}

func TestZstdWrongDecompressData(t *testing.T) {

	data, err := generic.CSPRNG(16)
	r.NoError(t, err)

	reader := bytes.NewReader(data)
	var compressedBuff bytes.Buffer

	compressor := compression.Zstd{
		Level: 11,
	}

	err = compressor.DecompressStream(reader, &compressedBuff)
	r.Error(t, err)
}
