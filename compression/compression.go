package compression

import (
	"bytes"
	"compress/gzip"
	"io"
)

func GzipCompress(src []byte, level int) ([]byte, error) {
	var b bytes.Buffer
	gz, err := gzip.NewWriterLevel(&b, level)
	if err != nil {
		return []byte{}, err
	}
	if _, err := gz.Write(src); err != nil {
		return []byte{}, err
	}
	if err := gz.Close(); err != nil {
		return []byte{}, err
	}

	return b.Bytes(), nil
}

func GzipDecompress(src []byte) ([]byte, error) {
	rdata := bytes.NewReader(src)
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return []byte{}, err
	}
	s, err := io.ReadAll(r)
	if err != nil {
		return []byte{}, err
	}

	return s, nil
}
