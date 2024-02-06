package compression_test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/D3vl0per/crypt/asymmetric"
	"github.com/D3vl0per/crypt/compression"
	"github.com/D3vl0per/crypt/generic"

	r "github.com/stretchr/testify/require"
)

type compressor struct {
	name       string
	compressor compression.Compressor
	modes      []int
}

func compressionArlgorithms() []compressor {
	genericModes := []int{compression.BestCompression, compression.BestSpeed, compression.NoCompression, compression.DefaultCompression, compression.HuffmanOnly}
	zstdModes := []int{compression.ZstdSpeedBestCompression, compression.ZstdSpeedBetterCompression, compression.ZstdSpeedDefault, compression.ZstdSpeedFastest}
	brotliModes := []int{compression.BrotliBestCompression, compression.BrotliDefaultCompression, compression.BrotliBestSpeed}

	compressors := []compressor{
		{
			name:       "zlib",
			compressor: &compression.Zlib{},
			modes:      genericModes,
		},
		{
			name:       "gzip",
			compressor: &compression.Gzip{},
			modes:      genericModes,
		},
		{
			name:       "zstd",
			compressor: &compression.Zstd{},
			modes:      zstdModes,
		},
		{
			name:       "generic",
			compressor: &compression.Flate{},
			modes:      genericModes,
		},
		{
			name:       "brotli",
			compressor: &compression.Brotli{},
			modes:      brotliModes,
		},
	}
	return compressors
}

type compressionSample struct {
	name string
	data []byte
}

func compressionSamples() []compressionSample {

	ed25519 := asymmetric.Ed25519{}
	if err := ed25519.Generate(); err != nil {
		panic(err)
	}

	testData := []compressionSample{
		{
			name: "random-data",
			data: []byte("PSGIeAYZuvDa2QScJkAI1S824E0fA8M2aAYH3SdMd9mWlETmDIgfbexxT5nwygIDIHFp5A92V6Ke4Sl7FwsOU5ox7IIhReltbLONZutz0EbnN3TiquWz3QJjNlo0HJ1t"),
		},
		{
			name: "zero-data",
			data: []byte("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		},
		{
			name: "bi-state-data",
			data: []byte("10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010"),
		},
		{
			name: "ascii-data",
			data: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscin"),
		},
		{
			name: "ed25519-secret-key",
			data: ed25519.SecretKey,
		},
		{
			name: "ed15519-public-key",
			data: ed25519.PublicKey,
		},
	}
	return testData
}

func BenchmarkRoundTrip(b *testing.B) {
	compressors := compressionArlgorithms()
	compressionSamples := compressionSamples()

	for _, compressor := range compressors {
		for _, mode := range compressor.modes {
			compressor.compressor.SetLevel(mode)
			for _, sample := range compressionSamples {
				b.Run(compressor.name+"-"+strconv.Itoa(mode)+"-"+sample.name, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						benchmarkRoundTrip(b, compressor.compressor, sample.data)
					}
				})
			}
		}
	}
}

func benchmarkRoundTrip(b *testing.B, compressor compression.Compressor, data []byte) {

	compressed, err := compressor.Compress(data)
	r.NoError(b, err)

	var compressedBuff bytes.Buffer
	var decompressedBuff bytes.Buffer
	reader := bytes.NewReader(data)

	err = compressor.CompressStream(reader, &compressedBuff)
	r.NoError(b, err)

	r.Equal(b, compressed, compressedBuff.Bytes())

	compressedReader := bytes.NewReader(compressedBuff.Bytes())

	decompressed, err := compressor.Decompress(compressed)
	r.NoError(b, err)

	err = compressor.DecompressStream(compressedReader, &decompressedBuff)
	r.NoError(b, err)

	r.Equal(b, decompressed, decompressedBuff.Bytes())

	r.Len(b, decompressedBuff.Bytes(), len(data))
	r.Equal(b, decompressedBuff.Bytes(), data)
}

func TestRoundTrips(t *testing.T) {
	compressors := compressionArlgorithms()
	compressionSamples := compressionSamples()

	for _, compressor := range compressors {
		for _, mode := range compressor.modes {
			compressor.compressor.SetLevel(mode)
			for _, sample := range compressionSamples {
				t.Run(compressor.name+"-"+strconv.Itoa(mode)+"-"+sample.name, func(t *testing.T) {
					testRoundTrip(t, compressor.compressor, sample.data)
				})
			}
		}
	}
}

func testRoundTrip(t *testing.T, compressor compression.Compressor, data []byte) {

	compressed, err := compressor.Compress(data)
	r.NoError(t, err)

	var compressedBuff bytes.Buffer
	var decompressedBuff bytes.Buffer
	reader := bytes.NewReader(data)

	err = compressor.CompressStream(reader, &compressedBuff)
	r.NoError(t, err)

	r.Equal(t, compressed, compressedBuff.Bytes())

	t.Log("Compressor name: ", compressor.GetName())
	t.Log("Data sample: ", data[:16])
	t.Log("Orignal size: ", len(data))
	t.Log("Compressed size: ", compressedBuff.Len())
	t.Log("Compression mode: ", compressor.GetLevel())
	t.Log("---")
	compressedReader := bytes.NewReader(compressedBuff.Bytes())

	decompressed, err := compressor.Decompress(compressed)
	r.NoError(t, err)

	err = compressor.DecompressStream(compressedReader, &decompressedBuff)
	r.NoError(t, err)

	r.Equal(t, decompressed, decompressedBuff.Bytes())

	r.Len(t, decompressedBuff.Bytes(), len(data))
	r.Equal(t, decompressedBuff.Bytes(), data)

	t.Log("=============")
}

func TestRoundTripsFault(t *testing.T) {
	type cases struct {
		name        string
		level       int
		data        []byte
		expectedErr string
	}

	type testStructue struct {
		name       string
		compressor compression.Compressor
		compress   []cases
		decompress []cases
	}

	testCases := []testStructue{
		{
			name:       "gzip",
			compressor: &compression.Gzip{},
			compress: []cases{
				{
					name:        "level 10, invalid level",
					level:       10,
					data:        []byte("test"),
					expectedErr: "gzip: invalid compression level: 10",
				},
				{
					name:        "level -4, invalid level",
					level:       -4,
					data:        []byte("test"),
					expectedErr: "gzip: invalid compression level: -4",
				},
			},
		},
		{
			name:       "zsdt",
			compressor: &compression.Zstd{},
			decompress: []cases{
				{
					name:        "invalid payload, invalid header",
					data:        make([]byte, 32),
					level:       1,
					expectedErr: "invalid input: magic number mismatch",
				},
			},
		},
		{
			name:       "flate",
			compressor: &compression.Flate{},
			compress: []cases{
				{
					name:        "level 10, invalid level",
					level:       10,
					data:        []byte("test"),
					expectedErr: "flate: invalid compression level 10: want value in range [-2, 9]",
				},
				{
					name:        "level -3, invalid level",
					level:       -3,
					data:        []byte("test"),
					expectedErr: "flate: invalid compression level -3: want value in range [-2, 9]",
				},
			},
			decompress: []cases{
				{
					name:        "invalid payload, invalid header",
					data:        make([]byte, 32),
					level:       1,
					expectedErr: "invalid header",
				},
			},
		},
		{
			name:       "zlib",
			compressor: &compression.Zlib{},
			compress: []cases{
				{
					name:        "level 10, invalid level",
					level:       10,
					data:        []byte("test"),
					expectedErr: "invalid compression level",
				},
				{
					name:        "level -3, invalid level",
					level:       -3,
					data:        []byte("test"),
					expectedErr: "invalid compression level",
				},
			},
		},
		{
			name:       "brotli",
			compressor: &compression.Brotli{},
			decompress: []cases{
				{
					name:        "invalid payload, invalid header",
					data:        make([]byte, 32),
					level:       1,
					expectedErr: "invalid header",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range tc.compress {
				t.Run(c.name, func(t *testing.T) {
					tc.compressor.SetLevel(c.level)
					_, err := tc.compressor.Compress(c.data)
					r.Error(t, err)
				})
			}
			for _, c := range tc.decompress {
				t.Run(c.name, func(t *testing.T) {
					tc.compressor.SetLevel(c.level)
					_, err := tc.compressor.Decompress(c.data)
					r.Error(t, err)
				})
			}
		})
	}
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
