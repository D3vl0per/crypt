package aged

// FiloSottile age encryption header obfuscation.
import (
	"bytes"
	"errors"
)

type Obfuscation interface {
	Obfuscate([]byte) ([]byte, error)
	Deobfuscate([]byte) ([]byte, error)
}

// AgeV1Obf is a obfuscation for age encryption header
type AgeV1Obf struct{}

var (
	//nolint:gochecknoglobals
	endOfHeader = []byte{45, 45, 45, 32}
	//nolint:gochecknoglobals
	endFlag = []byte{0, 255, 1, 254}
)

//nolint:gochecknoglobals
const lengthOfKey = 47

func (a *AgeV1Obf) Obfuscate(payload []byte) ([]byte, error) {

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
	// nolint:gocritic
	obfHeader := append(pad, endFlag...)
	return bytes.ReplaceAll(payload, header, obfHeader), nil
}

func (a *AgeV1Obf) Deobfuscate(payload []byte) ([]byte, error) {
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
