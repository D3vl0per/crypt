package compression

import (
	"bytes"
	"io"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

type Compressor interface {
	Compress([]byte) ([]byte, error)
	Decompress([]byte) ([]byte, error)
	CompressStream(io.Reader, io.Writer) error
	DecompressStream(io.Reader, io.Writer) error
	GetLevel() int
}

type Gzip struct {
	Level int
}

func (g *Gzip) Compress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var compressedBuff bytes.Buffer

	err := g.CompressStream(reader, &compressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return compressedBuff.Bytes(), nil
}

func (g *Gzip) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := gzip.NewWriterLevel(out, g.Level)
	if err != nil {
		return err
	}

	_, err = io.Copy(enc, in)
	if err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

func (g *Gzip) Decompress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var deCompressedBuff bytes.Buffer

	err := g.DecompressStream(reader, &deCompressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return deCompressedBuff.Bytes(), nil
}

func (g *Gzip) DecompressStream(in io.Reader, out io.Writer) error {
	d, err := gzip.NewReader(in)
	if err != nil {
		d.Close()
		return err
	}
	defer d.Close()
	_, err = io.Copy(out, d)
	return err
}

func (g *Gzip) GetLevel() int {
	return g.Level
}

type Zstd struct {
	Level int
}

func (z *Zstd) Compress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var compressedBuff bytes.Buffer

	err := z.CompressStream(reader, &compressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return compressedBuff.Bytes(), nil
}

func (z *Zstd) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := zstd.NewWriter(out, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(z.Level)))
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

func (z *Zstd) Decompress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var deCompressedBuff bytes.Buffer

	err := z.DecompressStream(reader, &deCompressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return deCompressedBuff.Bytes(), nil
}

func (z *Zstd) DecompressStream(in io.Reader, out io.Writer) error {
	d, err := zstd.NewReader(in)
	if err != nil {
		d.Close()
		return err
	}
	defer d.Close()
	_, err = io.Copy(out, d)
	return err
}

func (z *Zstd) GetLevel() int {
	return z.Level
}

type Flate struct {
	Level int
}

func (f *Flate) Compress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var compressedBuff bytes.Buffer

	err := f.CompressStream(reader, &compressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return compressedBuff.Bytes(), nil
}

func (f *Flate) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := flate.NewWriter(out, f.Level)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

func (f *Flate) Decompress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var deCompressedBuff bytes.Buffer

	err := f.DecompressStream(reader, &deCompressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return deCompressedBuff.Bytes(), nil
}

func (f *Flate) DecompressStream(in io.Reader, out io.Writer) error {
	d := flate.NewReader(in)
	defer d.Close()
	_, err := io.Copy(out, d)
	return err
}

func (f *Flate) GetLevel() int {
	return f.Level
}

type Zlib struct {
	Level int
}

func (zl *Zlib) Compress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var compressedBuff bytes.Buffer

	err := zl.CompressStream(reader, &compressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return compressedBuff.Bytes(), nil
}

func (zl *Zlib) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := zlib.NewWriterLevel(out, zl.Level)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}

func (zl *Zlib) Decompress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var deCompressedBuff bytes.Buffer

	err := zl.DecompressStream(reader, &deCompressedBuff)
	if err != nil {
		return []byte{}, nil
	}

	return deCompressedBuff.Bytes(), nil
}

func (zl *Zlib) DecompressStream(in io.Reader, out io.Writer) error {
	d, err := zlib.NewReader(in)
	if err != nil {
		d.Close()
		return err
	}
	defer d.Close()
	_, err = io.Copy(out, d)
	return err
}

func (zl *Zlib) GetLevel() int {
	return zl.Level
}
