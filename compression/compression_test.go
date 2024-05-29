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

func compressors() []compression.Compressor {
	return []compression.Compressor{
		&compression.Zlib{},
		&compression.Gzip{},
		&compression.Zstd{},
		&compression.Flate{},
		&compression.Brotli{},
	}
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
			name: "ed25519-public-key",
			data: ed25519.PublicKey,
		},
	}
	return testData
}

func BenchmarkRoundTrip(b *testing.B) {
	compressors := compressors()
	compressionSamples := compressionSamples()

	for _, compressor := range compressors {
		for _, mode := range compressor.GetModes() {
			compressor.SetLevel(mode)
			for _, sample := range compressionSamples {
				b.Run(compressor.GetName()+"/"+strconv.Itoa(mode)+"/"+sample.name, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						benchmarkRoundTrip(b, compressor, sample.data)
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
	compressors := compressors()
	compressionSamples := compressionSamples()

	for _, compressor := range compressors {
		for _, mode := range compressor.GetModes() {
			compressor.SetLevel(mode)
			for _, sample := range compressionSamples {
				t.Run(compressor.GetName()+"/"+strconv.Itoa(mode)+"/"+sample.name, func(t *testing.T) {
					testRoundTrip(t, compressor, sample.data)
				})
			}
		}
	}
}

func TestInterfacelessRoundTrip(t *testing.T) {
	compressors := []compression.Compressor{
		&compression.Zlib{Level: compression.DefaultCompression},
		&compression.Gzip{Level: compression.DefaultCompression},
		&compression.Zstd{Level: compression.ZstdSpeedDefault},
		&compression.Flate{Level: compression.DefaultCompression},
		&compression.Brotli{Level: compression.BrotliDefaultCompression},
	}
	samples := compressionSamples()

	for _, compressor := range compressors {
		t.Run(compressor.GetName(), func(t *testing.T) {
			testRoundTrip(t, compressor, samples[0].data)
		})
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

	t.Log("Compressor name:", compressor.GetName())
	t.Log("Data sample:", data[:16])
	t.Log("Orignal size:", len(data))
	t.Log("Compressed size:", compressedBuff.Len())
	t.Log("Compression mode:", compressor.GetLevel())
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

func TestMissingCompressLevels(t *testing.T) {
	compressors := []compression.Compressor{
		&compression.Zstd{},
	}
	samples := compressionSamples()

	for _, compressor := range compressors {
		t.Run(compressor.GetName(), func(t *testing.T) {

			out, err := compressor.Compress(samples[0].data)
			r.ErrorIs(t, err, compression.ErrMissingCompressionLevel)
			r.Nil(t, out)
		})

		t.Run("streaming/"+compressor.GetName(), func(t *testing.T) {
			var out bytes.Buffer
			reader := bytes.NewReader(samples[0].data)

			err := compressor.CompressStream(reader, &out)
			r.ErrorIs(t, err, compression.ErrMissingCompressionLevel)
			r.Nil(t, out.Bytes())
		})
	}
}
