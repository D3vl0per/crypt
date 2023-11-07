package compression

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/klauspost/compress/zstd"
)

func GzipCompress(src []byte, level int) ([]byte, error) {
	var buff bytes.Buffer
	gzip, err := gzip.NewWriterLevel(&buff, level)
	if err != nil {
		return []byte{}, err
	}
	if _, err := gzip.Write(src); err != nil {
		return []byte{}, err
	}
	if err := gzip.Close(); err != nil {
		return []byte{}, err
	}

	return buff.Bytes(), nil
}

func GzipDecompress(src []byte) ([]byte, error) {
	rdata := bytes.NewReader(src)
	gzip, err := gzip.NewReader(rdata)
	if err != nil {
		return []byte{}, err
	}
	raw, err := io.ReadAll(gzip)
	if err != nil {
		return []byte{}, err
	}

	return raw, nil
}

func ZstdCompress(raw []byte, options ...zstd.EOption) ([]byte, error) {
	reader := bytes.NewReader(raw)
	var compressedBuff bytes.Buffer
	
	err := ZstdCompressStream(reader, &compressedBuff, options...)
	if err != nil{
		return []byte{}, nil
	}

	return compressedBuff.Bytes(), nil
}

func ZstdCompressStream(in io.Reader, out io.Writer, options ...zstd.EOption) error {
	enc, err := zstd.NewWriter(out, options...)
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

func ZstdDecompress(compressed []byte) ([]byte, error) {
	reader := bytes.NewReader(compressed)
	var deCompressedBuff bytes.Buffer
	
	err := ZstdDecompressStream(reader, &deCompressedBuff)
	if err != nil{
		return []byte{}, nil
	}

	return deCompressedBuff.Bytes(), nil
}

func ZstdDecompressStream(in io.Reader, out io.Writer) error {
	d, err := zstd.NewReader(in)
	if err != nil {
		d.Close()
		return err
	}
	defer d.Close()
	_, err = io.Copy(out, d)
	return err
}
