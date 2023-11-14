package generic

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
)

type Encoder interface {
	Encode([]byte) string
	Decode([]byte) ([]byte, error)
}

type Base64 struct{}
type Hex struct{}

func (b *Base64) Encode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

func (b *Base64) Decode(data string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(data)
}

func (h *Hex) Encode(data []byte) string {
	return hex.EncodeToString(data)
}

func (h *Hex) Decode(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

func Compare(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

func ExportECCPK(pk crypto.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	return hex.EncodeToString(pem.EncodeToMemory(block)), nil
}

func ExportECCSK(sk ed25519.PrivateKey) (string, error) {
	b, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	return hex.EncodeToString(pem.EncodeToMemory(block)), nil
}

func ImportECCPK(pk string) (ed25519.PublicKey, error) {
	pkPem, err := hex.DecodeString(pk)
	if err != nil {
		return ed25519.PublicKey{}, err
	}

	pemBlock, _ := pem.Decode(pkPem)

	pkRaw, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return ed25519.PublicKey{}, err
	}
	// nolint:errcheck
	pkC := pkRaw.(crypto.PublicKey)
	// nolint:errcheck
	return pkC.(ed25519.PublicKey), nil
}

func ImportECCSK(sk string) (ed25519.PublicKey, error) {
	skPem, err := hex.DecodeString(sk)
	if err != nil {
		return ed25519.PublicKey{}, err
	}

	pemBlock, _ := pem.Decode(skPem)

	pkRaw, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return ed25519.PublicKey{}, err
	}
	// nolint:errcheck
	pkC := pkRaw.(crypto.PublicKey)
	// nolint:errcheck
	return pkC.(ed25519.PublicKey), nil
}

func AllZero(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func StrCnct(str ...string) string {
	var buffer bytes.Buffer

	for _, e := range str {
		buffer.WriteString(e)
	}

	return buffer.String()
}
