package compression_test

import (
	"bytes"
	"testing"

	"github.com/D3vl0per/crypt/compression"
	"github.com/D3vl0per/crypt/generic"
	"github.com/klauspost/compress/zstd"

	r "github.com/stretchr/testify/require"
)

func TestGzipCompress(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")
	for i := 0; i <= 9; i++ {
		cmp, err := compression.GzipCompress(data, i)
		r.NoError(t, err)
		dcmp, err := compression.GzipDecompress(cmp)
		r.NoError(t, err)
		r.Equal(t, data, dcmp)
	}
}

func TestGzipWrongLevel(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")
	_, err := compression.GzipCompress(data, 10)
	r.EqualError(t, err, "gzip: invalid compression level: 10")
}

func TestZstdEndToEnd(t *testing.T) {
	modes := []int{11, 7, 3, 1}
	test := map[int][]byte{
		0: []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t"),
		1: []byte("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		2: []byte("10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010"),
	}
	for datai, data := range test {
		for _, elem := range modes {

			// Compression with ZstdCompress function
			compressed, err := compression.ZstdCompress(data, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(elem)))
			r.NoError(t, err)

			var compressedBuff bytes.Buffer
			var decompressedBuff bytes.Buffer
			reader := bytes.NewReader(data)

			// Compression with ZstdCompressStream function
			err = compression.ZstdCompressStream(reader, &compressedBuff, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(elem)))
			r.NoError(t, err)

			// Compression cross-check (ZstdCompress and ZstdCompressStream)
			r.Equal(t, compressed, compressedBuff.Bytes())

			t.Log("Data sample: ", datai)
			t.Log("Orignal size: ", len(data))
			t.Log("Compressed size: ", compressedBuff.Len())
			t.Log("Compression mode: ", elem)
			t.Log("---")
			compressedReader := bytes.NewReader(compressedBuff.Bytes())

			// Decompress with ZstdDecompress function
			decompressed, err := compression.ZstdDecompress(compressed)
			r.NoError(t, err)

			// Decompress with ZstdStream function
			err = compression.ZstdDecompressStream(compressedReader, &decompressedBuff)
			r.NoError(t, err)

			// Decompression cross-check (ZstdCompress and ZstdCompressStream)
			r.Equal(t, decompressed, decompressedBuff.Bytes())

			r.Len(t, decompressedBuff.Bytes(), len(data))
			r.Equal(t, decompressedBuff.Bytes(), data)
		}
		t.Log("=============")
	}
}

func TestZstdWrongLevel(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")

	reader := bytes.NewReader(data)
	var compressedBuff bytes.Buffer

	err := compression.ZstdCompressStream(reader, &compressedBuff, zstd.WithEncoderLevel(12))
	r.EqualError(t, err, "unknown encoder level")
}

func TestZstdWrongConcurrency(t *testing.T) {
	data := []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t")

	reader := bytes.NewReader(data)
	var compressedBuff bytes.Buffer

	err := compression.ZstdCompressStream(reader, &compressedBuff, zstd.WithEncoderConcurrency(-1))
	r.EqualError(t, err, "concurrency must be at least 1")
}

func TestZstdWrongDecompressData(t *testing.T) {

	data, err := generic.CSPRNG(16)
	r.NoError(t, err)

	reader := bytes.NewReader(data)
	var compressedBuff bytes.Buffer

	err = compression.ZstdDecompressStream(reader, &compressedBuff)
	r.Error(t, err)
}
