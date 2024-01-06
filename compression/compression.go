package compression

import (
	"bytes"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

const (
	// Predefined compression levels.
	//
	// Compatible with flate, gzip, zlib.
	NoCompression       int = 0
	BestSpeed           int = 1
	BestCompression     int = 9
	DefaultCompression  int = -1
	ConstantCompression int = -2
	HuffmanOnly         int = -2

	// Source: https://pkg.go.dev/github.com/klauspost/compress/gzip#pkg-constants
	//
	// StatelessCompression will do compression but without maintaining any state
	// between Write calls.
	// There will be no memory kept between Write calls,
	// but compression and speed will be suboptimal.
	// Because of this, the size of actual Write calls will affect output size.
	StatelessCompression int = -3

	// Zstd specific predefined compression levels.
	//
	// Compatible with only zstd.
	ZstdSpeedBestCompression   int = 11
	ZstdSpeedDefault           int = 3
	ZstdSpeedFastest           int = 1
	ZstdSpeedBetterCompression int = 7

	// Brotil specific predefined compression levels.
	//
	// Compatible with only brotli.
	BrotliBestCompression    int = 11
	BrotliDefaultCompression int = 6
	BrotliBestSpeed          int = 0
)

type Compressor interface {
	Compress([]byte) ([]byte, error)
	Decompress([]byte) ([]byte, error)
	CompressStream(io.Reader, io.Writer) error
	DecompressStream(io.Reader, io.Writer) error
	GetLevel() int
	SetLevel(int)
	GetName() string
}

type Gzip struct {
	Level            int
	compressedBuff   bytes.Buffer
	deCompressedBuff bytes.Buffer
}

func (g *Gzip) Compress(in []byte) ([]byte, error) {
	g.compressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := g.CompressStream(reader, &g.compressedBuff)
	if err != nil {
		return nil, nil
	}

	return g.compressedBuff.Bytes(), nil
}

func (g *Gzip) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := gzip.NewWriterLevel(out, g.Level)
	if err != nil {
		return err
	}

	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}

func (g *Gzip) Decompress(in []byte) ([]byte, error) {
	g.deCompressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := g.DecompressStream(reader, &g.deCompressedBuff)
	if err != nil {
		return nil, nil
	}

	return g.deCompressedBuff.Bytes(), nil
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

func (g *Gzip) SetLevel(level int) {
	g.Level = level
}

func (g *Gzip) GetName() string {
	return "gzip"
}

type Zstd struct {
	Level            int
	compressedBuff   bytes.Buffer
	deCompressedBuff bytes.Buffer
}

func (z *Zstd) Compress(in []byte) ([]byte, error) {
	z.compressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := z.CompressStream(reader, &z.compressedBuff)
	if err != nil {
		return nil, nil
	}

	return z.compressedBuff.Bytes(), nil
}

func (z *Zstd) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := zstd.NewWriter(out, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(z.Level)))
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}

func (z *Zstd) Decompress(in []byte) ([]byte, error) {
	z.deCompressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := z.DecompressStream(reader, &z.deCompressedBuff)
	if err != nil {
		return nil, nil
	}

	return z.deCompressedBuff.Bytes(), nil
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

func (z *Zstd) SetLevel(level int) {
	z.Level = level
}

func (z *Zstd) GetName() string {
	return "zstd"
}

type Flate struct {
	Level            int
	compressedBuff   bytes.Buffer
	deCompressedBuff bytes.Buffer
}

func (f *Flate) Compress(in []byte) ([]byte, error) {
	f.compressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := f.CompressStream(reader, &f.compressedBuff)
	if err != nil {
		return nil, nil
	}

	return f.compressedBuff.Bytes(), nil
}

func (f *Flate) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := flate.NewWriter(out, f.Level)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}

func (f *Flate) Decompress(in []byte) ([]byte, error) {
	f.deCompressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := f.DecompressStream(reader, &f.deCompressedBuff)
	if err != nil {
		return nil, nil
	}

	return f.deCompressedBuff.Bytes(), nil
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

func (f *Flate) SetLevel(level int) {
	f.Level = level
}

func (f *Flate) GetName() string {
	return "deflate"
}

type Zlib struct {
	Level            int
	compressedBuff   bytes.Buffer
	deCompressedBuff bytes.Buffer
}

func (zl *Zlib) Compress(in []byte) ([]byte, error) {
	zl.compressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := zl.CompressStream(reader, &zl.compressedBuff)
	if err != nil {
		return nil, nil
	}

	return zl.compressedBuff.Bytes(), nil
}

func (zl *Zlib) CompressStream(in io.Reader, out io.Writer) error {

	enc, err := zlib.NewWriterLevel(out, zl.Level)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}

func (zl *Zlib) Decompress(in []byte) ([]byte, error) {
	zl.deCompressedBuff.Reset()
	reader := bytes.NewReader(in)

	err := zl.DecompressStream(reader, &zl.deCompressedBuff)
	if err != nil {
		return nil, nil
	}

	return zl.deCompressedBuff.Bytes(), nil
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

func (zl *Zlib) SetLevel(level int) {
	zl.Level = level
}

func (zl *Zlib) GetName() string {
	return "zlib"
}

type Brotli struct {
	Level int
	bw    *brotli.Writer
	br    *brotli.Reader
}

func (b *Brotli) Compress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var compressedBuff bytes.Buffer

	err := b.CompressStream(reader, &compressedBuff)
	if err != nil {
		return nil, nil
	}

	return compressedBuff.Bytes(), nil
}
func (b *Brotli) CompressStream(in io.Reader, out io.Writer) error {

	b.bw.Reset(out)
	_, err := io.Copy(b.bw, in)
	if err != nil {
		return err
	}

	if err := b.bw.Close(); err != nil {
		return err
	}

	return nil
}
func (b *Brotli) Decompress(in []byte) ([]byte, error) {
	reader := bytes.NewReader(in)
	var deCompressedBuff bytes.Buffer

	err := b.DecompressStream(reader, &deCompressedBuff)
	if err != nil {
		return nil, nil
	}

	return deCompressedBuff.Bytes(), nil
}
func (b *Brotli) DecompressStream(in io.Reader, out io.Writer) error {

	if err := b.br.Reset(in); err != nil {
		return err
	}

	if _, err := io.Copy(out, b.br); err != nil {
		return err
	}
	return nil
}

func (b *Brotli) GetLevel() int {
	return b.Level
}

func (b *Brotli) SetLevel(level int) {
	b.bw = brotli.NewWriterLevel(nil, b.Level)
	b.br = brotli.NewReader(nil)
}

func (b *Brotli) GetName() string {
	return "br"
}

// In progress
/*
type FSE struct {
	DecompressLimit   int
	compressScratch   fse.Scratch
	decompressScratch fse.Scratch
}

func (f *FSE) Compress(in []byte) ([]byte, error) {

	f.compressScratch.Out = nil
	_, err := fse.Compress(in, &f.compressScratch)
	if err != nil {
		return nil, err
	}

	return f.compressScratch.Out, nil
}

func (f *FSE) CompressStream(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	f.compressScratch.Out = nil
	_, err = fse.Compress(data, &f.compressScratch)
	if err != nil {
		return err
	}

	_, err = out.Write(f.compressScratch.Out)
	return err
}

func (f *FSE) Decompress(in []byte) ([]byte, error) {
	f.decompressScratch.Out = nil
	f.decompressScratch.DecompressLimit = f.DecompressLimit

	_, err := fse.Decompress(in, &f.decompressScratch)
	if err != nil {
		return nil, err
	}
	return f.decompressScratch.Out, nil
}

func (f *FSE) DecompressStream(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	f.decompressScratch.Out = nil
	f.decompressScratch.DecompressLimit = f.DecompressLimit
	_, err = fse.Decompress(data, &f.decompressScratch)
	if err != nil {
		return err
	}

	_, err = out.Write(f.decompressScratch.Out)
	return err
}

func (f *FSE) GetLevel() int {
	return f.DecompressLimit
}

func (f *FSE) SetLevel(level int) {
	f.DecompressLimit = level
}

func (f *FSE) GetName() string {
	return "fse"
}

type Huff0X1 struct {
	compressScratch   huff0.Scratch
	decompressScratch huff0.Scratch
}

func (h *Huff0X1) Compress(in []byte) ([]byte, error) {
	h.decompressScratch.Out = nil
	h.decompressScratch.OutData = nil
	h.decompressScratch.OutTable = nil
	h.decompressScratch.Reuse = huff0.ReusePolicyNone

	_, _, err := huff0.Compress1X(in, &h.compressScratch)
	if err != nil {
		return nil, err
	}

	return h.compressScratch.Out, nil
}

func (h *Huff0X1) CompressStream(in io.Reader, out io.Writer) error {
	h.decompressScratch.Out = nil
	h.decompressScratch.OutData = nil
	h.decompressScratch.OutTable = nil
	h.decompressScratch.Reuse = huff0.ReusePolicyNone

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	_, _, err = huff0.Compress1X(data, &h.compressScratch)
	if err != nil {
		return err
	}

	_, err = out.Write(h.compressScratch.Out)
	return err
}

func (h *Huff0X1) Decompress(in []byte) ([]byte, error) {
	h.decompressScratch.Out = nil
	h.decompressScratch.OutData = nil
	h.decompressScratch.OutTable = nil
	h.decompressScratch.Reuse = huff0.ReusePolicyNone

	var err error
	var remain []byte
	_, remain, err = huff0.ReadTable(in, &h.decompressScratch)
	if err != nil {
		return nil, nil
	}

	out, err := h.decompressScratch.Decompress1X(remain)
	if err != nil {
		return nil, nil
	}

	return out, nil
}

func (h *Huff0X1) DecompressStream(in io.Reader, out io.Writer) error {
	h.decompressScratch.Out = nil
	h.decompressScratch.OutData = nil
	h.decompressScratch.OutTable = nil
	h.decompressScratch.Reuse = huff0.ReusePolicyNone

	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	var remain []byte
	_, remain, err = huff0.ReadTable(data, &h.decompressScratch)
	if err != nil {
		return err
	}

	raw, err := h.decompressScratch.Decompress1X(remain)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, bytes.NewReader(raw))
	return err
}

func (h *Huff0X1) GetLevel() int {
	return 0
}

func (h *Huff0X1) SetLevel(level int) {

}

func (h *Huff0X1) GetName() string {
	return "huff0"
}
*/
