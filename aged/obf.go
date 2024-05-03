package aged

// FiloSottile age encryption header obfuscation.
import (
	"bytes"
	"errors"
)

// Age keyslot header obfuscation
type Obfuscation interface {
	Obfuscate([]byte) ([]byte, error)
	Deobfuscate([]byte) ([]byte, error)
}

// AgeV1Obf is a obfuscation for age encryption header.
type AgeV1Obf struct{}

type CustomObf struct {
	Encoder func([]byte) ([]byte, error)
	Decoder func([]byte) ([]byte, error)
}

var (
	//nolint:gochecknoglobals
	endOfHeader = []byte{45, 45, 45, 32}
	//nolint:gochecknoglobals
	endFlag = []byte{0, 255, 1, 254}
)

const lengthOfKey = 47

var ErrMissingFlag = errors.New("missing end flag")
var ErrInvalidHeaderLength = errors.New("invalid header length")
var ErrInvalidHeader = errors.New("invalid header")

func (a *AgeV1Obf) Obfuscate(payload []byte) ([]byte, error) {
	headerIndex := bytes.Index(payload, endOfHeader)
	if headerIndex == -1 {
		return nil, ErrMissingFlag
	}
	if headerIndex+lengthOfKey > len(payload) {
		return nil, ErrInvalidHeaderLength
	}
	header := payload[:headerIndex+lengthOfKey]
	pad := make([]byte, len(header))

	var counter byte
	for i, e := range header {
		pad[i] = e ^ counter
		counter--
	}
	//nolint:gocritic
	obfHeader := append(pad, endFlag...)
	return bytes.ReplaceAll(payload, header, obfHeader), nil
}

func (a *AgeV1Obf) Deobfuscate(payload []byte) ([]byte, error) {
	headerIndex := bytes.Index(payload, endFlag)
	if headerIndex == -1 {
		return nil, ErrMissingFlag
	}
	if headerIndex+len(endFlag) > len(payload) {
		return nil, ErrInvalidHeader
	}
	header := payload[:headerIndex+len(endFlag)]
	if len(header) < len(endFlag) {
		return nil, ErrInvalidHeaderLength
	}

	pad := make([]byte, len(header)-len(endFlag))

	var counter byte
	for i, e := range header[:len(header)-len(endFlag)] {
		pad[i] = e ^ counter
		counter--
	}

	return bytes.ReplaceAll(payload, header, pad), nil
}

func (c *CustomObf) Obfuscate(payload []byte) ([]byte, error) {
	if c.Encoder == nil {
		return nil, ErrMissingFlag
	}
	return c.Encoder(payload)
}

func (c *CustomObf) Deobfuscate(payload []byte) ([]byte, error) {
	if c.Decoder == nil {
		return nil, ErrMissingFlag
	}
	return c.Decoder(payload)
}
