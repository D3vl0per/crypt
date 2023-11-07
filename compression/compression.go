package compression

import (
	"bytes"
	"compress/gzip"
	"io"
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
