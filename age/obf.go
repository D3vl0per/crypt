package age

// FiloSottile age encryption header obfuscation.
import (
	"bytes"
	"errors"
)

var (
	//nolint:gochecknoglobals
	endOfHeader  = []byte{45, 45, 45, 32}
	//nolint:gochecknoglobals
	endFlag     = []byte{0, 255, 1, 254}
)
//nolint:gochecknoglobals
const lengthOfKey = 47


func ObfHeader(payload []byte) ([]byte, error) {
	headerIndex := bytes.Index(payload, endOfHeader)
	if headerIndex == -1 {
		return []byte{}, errors.New("missing end flag")
	}
	if headerIndex+lengthOfKey > len(payload) {
		return []byte{}, errors.New("invalid header length")
	}
	header := payload[:headerIndex+lengthOfKey]
	pad := make([]byte, len(header))

	var counter byte
	for i, e := range header {
		pad[i] = e ^ counter
		counter--
	}
	// nolint:makezero
	obfHeader := append(pad, endFlag...)
	return bytes.ReplaceAll(payload, header, obfHeader), nil
}

func DeobfHeader(payload []byte) ([]byte, error) {
	headerIndex := bytes.Index(payload, endFlag)
	if headerIndex == -1 {
		return []byte{}, errors.New("missing end flag")
	}
	if headerIndex+len(endFlag) > len(payload) {
		return []byte{}, errors.New("invalid header")
	}
	header := payload[:headerIndex+len(endFlag)]
	if len(header) < len(endFlag) {
		return []byte{}, errors.New("invalid header length")
	}

	pad := make([]byte, len(header)-len(endFlag))

	var counter byte
	for i, e := range header[:len(header)-len(endFlag)] {
		pad[i] = e ^ counter
		counter--
	}

	return bytes.ReplaceAll(payload, header, pad), nil
}
