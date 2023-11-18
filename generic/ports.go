package generic

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

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
